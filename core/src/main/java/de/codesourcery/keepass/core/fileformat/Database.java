/**
 * Copyright 2020 Tobias Gierke <tobias.gierke@code-sourcery.de>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.codesourcery.keepass.core.fileformat;

import de.codesourcery.keepass.core.Constants;
import de.codesourcery.keepass.core.crypto.ChaCha20;
import de.codesourcery.keepass.core.crypto.CipherStreamFactory;
import de.codesourcery.keepass.core.crypto.CompositeKey;
import de.codesourcery.keepass.core.crypto.Credential;
import de.codesourcery.keepass.core.crypto.HMACInputStream;
import de.codesourcery.keepass.core.crypto.HMACOutputStream;
import de.codesourcery.keepass.core.crypto.Hash;
import de.codesourcery.keepass.core.crypto.IStreamCipher;
import de.codesourcery.keepass.core.crypto.MasterKey;
import de.codesourcery.keepass.core.crypto.OuterEncryptionAlgorithm;
import de.codesourcery.keepass.core.crypto.Salsa20;
import de.codesourcery.keepass.core.crypto.kdf.KeyDerivationFunction;
import de.codesourcery.keepass.core.datamodel.MemoryProtection;
import de.codesourcery.keepass.core.util.IResource;
import de.codesourcery.keepass.core.util.Logger;
import de.codesourcery.keepass.core.util.LoggerFactory;
import de.codesourcery.keepass.core.util.Misc;
import de.codesourcery.keepass.core.util.Serializer;
import de.codesourcery.keepass.core.util.Version;
import de.codesourcery.keepass.core.util.XmlHelper;
import org.apache.commons.lang3.Validate;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.crypto.BadPaddingException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

public class Database
{
    private static final Logger LOG = LoggerFactory.getLogger(Database.class );

    private static volatile boolean warmupDone;

    private static final int MAGIC = 0x9aa2d903;

    public IResource resource;
    public final FileHeader outerHeader = new FileHeader();
    public InnerHeader innerHeader = new InnerHeader(); // available in file format >= V4 only
    public final List<PayloadBlock> payloadBlocks =new ArrayList<>();

    public Database() {
    }

    public Database(IResource resource) {
        Validate.notNull( resource, "resource must not be null" );
        this.resource = resource;
    }

    public static Database read(List<Credential> credentials, IResource resource) throws IOException, BadPaddingException {
        return read( credentials, resource, false );
    }

    /**
     * Load database.
     *
     * @param credentials Credentials to use for decryption.
     * @param resource resource to read database from
     * @param doNotDecrypt set to <code>true</code> to return as soon as no more data can be decoded from the file without
     *                     knowing the right master password.
     * @return database
     * @throws IOException
     * @throws BadPaddingException thrown if decrypting the database failed because the provided credentials were wrong
     */
    public static Database read(List<Credential> credentials, IResource resource, boolean doNotDecrypt) throws IOException, BadPaddingException
    {
        LOG.info("Loading " + resource);
        final Database result = new Database( resource );
        try ( final Serializer buffer = new Serializer( resource.createInputStream() ) ) {
            result.read( credentials, buffer, doNotDecrypt );
        }
        return result;
    }

    public void write(List<Credential> credentials,
                      Serializer buffer,
                      Duration minKeyDerivationTime,
                      Logger progressLogger) throws IOException {
        try ( buffer ) {
            doWrite(credentials, buffer, minKeyDerivationTime, progressLogger,false);
        }
    }

    private void doWrite(List<Credential> credentials,
                         Serializer buffer,
                         Duration minKeyDerivationTime,
                         Logger progressLogger,
                         boolean doHeaderHashCalculationOnly) throws IOException
    {
        if ( ! doHeaderHashCalculationOnly && credentials.isEmpty() ) {
            throw new IllegalArgumentException("Missing credentials");
        }
        Validate.notNull(buffer, "buffer must not be null");
        Validate.notNull(progressLogger, "progressLogger must not be null");

        if ( ! doHeaderHashCalculationOnly && minKeyDerivationTime != null )
        {
            // warm-up JVM before we start measuring execution times
            if ( ! warmupDone )
            {
                final KeyDerivationFunctionId kdf = outerHeader.getKDF();
                long ts = System.currentTimeMillis();
                deriveMasterKey(credentials, kdf, 100, true);
                long loopTimeMillis = System.currentTimeMillis() - ts;
                final int innerRounds = (int) Math.max(1, 1000/loopTimeMillis);

                for (int i = 0; i < 5; i++)
                {
                    deriveMasterKey(credentials, kdf, innerRounds, true);
                }
                warmupDone = true;
            }
            while(true)
            {
                final long iterationCount = getTransformRounds();
                if ( iterationCount < 1 ) { // maybe we overflowed ?
                    throw new RuntimeException("Iteration count should never be or become negative");
                }
                final long now = System.currentTimeMillis();
                deriveMasterKey(credentials,false);
                final long elapsedMillis = System.currentTimeMillis() - now;
                if ( elapsedMillis >= minKeyDerivationTime.toMillis() )
                {
                    LOG.info("Using "+iterationCount+" iterations ["+elapsedMillis+" ms]");
                    progressLogger.success("Using "+iterationCount+" iterations ["+elapsedMillis+" ms]");
                    break;
                }
                final String msg = "Key derivation with " + iterationCount + " rounds " +
                    "took " + elapsedMillis + " ms which is faster than the" +
                    " requested min. key derivation time of " + minKeyDerivationTime.toMillis() + " ms";
                progressLogger.debug(msg);
                LOG.debug("doWrite(): " + msg);
                final float increment = iterationCount*0.01f;
                final long newIterationCount = iterationCount + (long) increment;
                if ( newIterationCount <= iterationCount ) {
                    throw new RuntimeException("Internal error, rounds counter must never be decreased here");
                }
                setTransformRounds( newIterationCount );
            }
            // KDBX v3.1 stores the header checksum as part of the XML payload
            // so we need to adjust it here as we might've changed the number of KDF rounds.

            // KDBX v4+ does not store the header hash as part of the payload anymore
            if ( getAppVersion().major() < 4 )
            {
                new XmlPayloadView( this ).setHeaderHash( calculateHeaderHash() );
            }
        }

        // write magic
        buffer.setWriteCopyToTmpBuffer( true );
        buffer.writeInt(MAGIC);

        // write header version
        buffer.writeInt( outerHeader.headerVersion.magic);

        // write app version
        buffer.writeShort( outerHeader.appVersion.minor() );
        buffer.writeShort( outerHeader.appVersion.major() );

        // write header entries
        final Misc.ThrowingBiConsumer<TLV<TLV.OuterHeaderType>,Serializer> outerHeaderWriter;
        if ( getAppVersion().major() < 4 ) {
            outerHeaderWriter = TLV::writeV3;
        } else {
            outerHeaderWriter = TLV::writeV4;
        }
        for ( TLV<TLV.OuterHeaderType> tlv : outerHeader.headerEntries.values() ) {
            outerHeaderWriter.consume( tlv, buffer );
        }

        if ( doHeaderHashCalculationOnly ) {
            return;
        }

        byte[] hmacKey = new byte[0];
        final MasterKey masterKey = deriveMasterKey(credentials,false);
        if ( getAppVersion().major() >= 4 )
        {
            final byte[] headerData = buffer.getTmpBuffer();

            // write header hash (SHA-256)
            buffer.writeBytes( calculateHeaderHash() );
            hmacKey = hmacKey( this.outerHeader.get( TLV.OuterHeaderType.MASTER_SEED ), masterKey.transformedKey );

            final byte[] headerHmac = calculateHMAC256( headerData,
                HMACInputStream.getHMacKey( 0xffffffff_ffffffffL, hmacKey ) );

            // store HMAC-256
            buffer.writeBytes( headerHmac );
        }
        buffer.setWriteCopyToTmpBuffer( false );

        // write XML payload part
        final ByteArrayOutputStream xmlPayload = new ByteArrayOutputStream();
        try ( Serializer tmp = new Serializer(xmlPayload) )
        {
            if ( getAppVersion().major() < 4 )
            {
                xmlPayload.write( outerHeader.get( TLV.OuterHeaderType.STREAM_START_BYTES ).rawValue );
                for (PayloadBlock block : payloadBlocks)
                {
                    block.write(tmp);
                }
            } else {
                final List<PayloadBlock> xml = payloadBlocks.stream().filter( block -> block.blockId == PayloadBlock.BLOCK_ID_PAYLOAD )
                    .collect( Collectors.toList() );
                if ( xml.size() != 1 ) {
                    throw new IllegalStateException( "Expected exactly one payload block, got " + xml.size() );
                }
                tmp.writeBytes( xml.get( 0 ).getDecompressedPayload() );
            }
        }

        byte[] payload = xmlPayload.toByteArray();
        final byte[] encryptionIV = outerHeader.get( TLV.OuterHeaderType.ENCRYPTION_IV ).rawValue;

        final Misc.IOFunction<OutputStream, OutputStream> encryptedOutputStream =
            toWrap -> CipherStreamFactory.encryptOutputStream( outerHeader.getOuterEncryptionAlgorithm(), masterKey, encryptionIV, toWrap );

        if ( getAppVersion().major() >= 4 )
        {
            // KDBX v4 -> payload is inner header followed by XML
            final ByteArrayOutputStream innerHeaders = new ByteArrayOutputStream();
            final Serializer innerHeaderSerializer = new Serializer( innerHeaders );
            if ( getAppVersion().major() >= 4 ) {
                for ( final TLV<TLV.InnerHeaderType> tlv : innerHeader.entries )
                {
                    tlv.writeV4( innerHeaderSerializer );
                }
            }
            payload = Misc.concat( innerHeaders.toByteArray(), payload );

            // 3. wrap with HMAC output stream
            buffer.wrapOutputStream( hmacKey, HMACOutputStream::new );

            // 2. encrypt
            buffer.wrapOutputStream( encryptedOutputStream );

            // 1. compress is necessary
            if ( outerHeader.isCompressedPayload() )
            {
                buffer.wrapOutputStream( GZIPOutputStream::new );
            }
        } else {
            // encrypt
            buffer.wrapOutputStream( encryptedOutputStream );
        }
        buffer.writeBytes( payload );
    }

    private MasterKey deriveMasterKey(List<Credential> credentials,boolean isBenchmark)
    {
        Validate.isTrue(!credentials.isEmpty(),"No credentials given?");
        final long rounds = getTransformRounds();
        final KeyDerivationFunctionId kdf = outerHeader.getKDF();
        return deriveMasterKey(credentials, kdf, rounds,isBenchmark);
    }

    private MasterKey deriveMasterKey(List<Credential> credentials, KeyDerivationFunctionId kdf, long rounds, boolean isBenchmark)
    {
        final CompositeKey compositeKey = CompositeKey.create(credentials);
        final TLV<TLV.OuterHeaderType> masterSeed = outerHeader.get( TLV.OuterHeaderType.MASTER_SEED );

        VariantDictionary dictionary = new VariantDictionary();
        final byte[] transformSeed;
        if ( outerHeader.isV3() )
        {
            transformSeed = outerHeader.get( TLV.OuterHeaderType.TRANSFORM_SEED ).rawValue;
        } else {
            dictionary = outerHeader.getKdfParams();
            transformSeed = switch( kdf ) {
                case AES_KDBX3, AES_KDBX4 -> dictionary.get( VariantDictionary.KDF_AES_SEED ).getJavaValue( byte[].class );
                case ARGON2D -> masterSeed.rawValue; // not used by my KDF implementation
                default -> throw new IllegalStateException( "KDF not implemented: " + kdf );
            };
        }
        final KeyDerivationFunction kdfFunc = KeyDerivationFunction.create( kdf );
        kdfFunc.init( rounds, transformSeed, isBenchmark, dictionary );
        byte[] kdfResult = kdfFunc.transform( compositeKey.data );

        final byte[] transformedKey = Misc.concat( masterSeed.rawValue, kdfResult );
        final byte[] finalKey = Hash.sha256(transformedKey);
        return new MasterKey( outerHeader.getOuterEncryptionAlgorithm(), finalKey, kdfResult );
    }

    private void read(List<Credential> credentials, Serializer buffer, boolean doNotDecrypt) throws IOException, BadPaddingException
    {
        Validate.notNull(credentials, "credentials must not be null");
        Validate.notNull(resource, "resource must not be null");

        buffer.setWriteCopyToTmpBuffer( true );

        // magic
        int value = buffer.readInt("4 bytes signature");

        if ( value != MAGIC ) {
            throw new IOException("Not a valid KeePassX file (invalid magic "+Integer.toHexString(value)+")");
        }

        // file header version
        value = buffer.readInt("4 bytes version");
        final Optional<FileHeader.Version> version = FileHeader.Version.lookup(value);
        if ( version.isEmpty() || ! version.get().isKeepass2() ) {
            throw new IOException("Unsupported file version 0x"+Integer.toHexString(value));
        }
        this.outerHeader.headerVersion = version.get();
        LOG.info("Header version: "+this.outerHeader.headerVersion);

        // app version
        final int appMinorVersion = buffer.readShort("app minor version");
        final int appMajorVersion = buffer.readShort("app major version");
        this.outerHeader.appVersion = new Version( appMajorVersion, appMinorVersion );

        LOG.info("App version: "+this.outerHeader.appVersion);

        // read header entries
        while ( true ) {
            final TLV<TLV.OuterHeaderType> tlv;
            if ( this.outerHeader.isV4() ) {
                // Note on V4: TLV structure now uses 4 bytes instead of 2 bytes (V3.1) to store length values
                // see https://keepass.info/help/kb/kdbx_4.html#innerhdr
                tlv = TLV.readV4( buffer , TLV.OuterHeaderType::lookup, TLV.OuterHeaderType.class );
            }
            else
            {
                tlv = TLV.read( buffer , TLV.OuterHeaderType::lookup, TLV.OuterHeaderType.class );
            }
            LOG.debug( "Found header: " + tlv );
            this.outerHeader.add(tlv);
            if ( tlv.hasType( TLV.OuterHeaderType.END_OF_HEADER ) ) {
                break;
            }
        }

        LOG.debug("Compressed payload: "+ this.outerHeader.isCompressedPayload() );
        LOG.debug("Outer encryption: "+ this.outerHeader.getOuterEncryptionAlgorithm());
        LOG.debug("Key Derivation Function: " + this.outerHeader.getKDF() );

        // sanity check
        if ( this.outerHeader.isV4() ) {
            final boolean foundV3OuterHeaderFields = this.outerHeader.headerEntries.keySet().stream().map( x -> switch( x ) {
                case PROTECTED_STREAM_KEY, TRANSFORM_ROUNDS, TRANSFORM_SEED, STREAM_START_BYTES, INNER_RANDOM_STREAM_ID -> true;
                default -> false;
            } ).reduce( false, (a, b) -> a|b );
            if ( foundV3OuterHeaderFields )
            {
                throw new RuntimeException( "Legacy header fields found in KDBX4 file ?" );
            }
        }

        byte[] hmacKey = null;
        final Supplier<MasterKey> finalKey = new Supplier<>()
        {
            private MasterKey key;
            @Override
            public MasterKey get()
            {
                if ( key == null )
                {
                    key = deriveMasterKey( credentials, false );
                }
                return key;
            }
        };
        if ( this.outerHeader.isV4() ) {
            // Note on V4: Directly after the KDBX 4 header, a (non-encrypted) SHA-256 hash of the header is stored now,
            // followed by the HMAC-SHA-256
            // This allows the detection of unintentional corruptions of the header (without knowing the master key).
            // The hash has no effect on the security.
            /*
In KDBX 4, header data is authenticated using HMAC-SHA-256.
Up to KDBX 3.1, header data was authenticated using a SHA-256 hash stored in the encrypted part of the database file.
The HMAC-SHA-256 approach used in KDBX 4 has various advantages. One advantage is that KeePass can verify the header
before trying to decrypt the remaining part, which prevents trying to decrypt incorrect data.

In KDBX 4, the HeaderHash element in the XML part is now obsolete and is not stored anymore. The new header authentication using HMAC-SHA-256 is mandatory.
Directly after the header, a (non-encrypted) SHA-256 hash of the header is stored (which allows the detection of unintentional corruptions,
without knowing the master key). Directly after the hash, the HMAC-SHA-256 value of the header is stored.
             */
            final byte[] headerData = buffer.getTmpBuffer();

            final byte[] actualSha256;
            try
            {
                actualSha256 = MessageDigest.getInstance( "SHA256" ).digest( headerData );
            }
            catch( NoSuchAlgorithmException e )
            {
                throw new RuntimeException( e );
            }
            final byte[] expectedSha256 = buffer.readBytes(256/8, "Expected SHA-256");
            LOG.debug( "SHA-256: " + Misc.toHexString( expectedSha256, "" ) );
            LOG.trace( "Actual SHA-256 header hash: " + Misc.toHexString( actualSha256, "") );
            if ( ! Arrays.equals( actualSha256, expectedSha256 ) ) {
                throw new RuntimeException( "Outer header data corrupted, SHA-256 hashes do not match" );
            }

            if ( doNotDecrypt ) {
                return;
            }

            // read HMAC-SHA-256
            final byte[] expectedHeaderHMAC = buffer.readBytes( 256 / 8, "Expected HMAC-SHA-256" );
            LOG.debug( "HMAC SHA-256: " + Misc.toHexString( expectedHeaderHMAC, "" ) );

            hmacKey = hmacKey( this.outerHeader.get( TLV.OuterHeaderType.MASTER_SEED ), finalKey.get().transformedKey );

            final byte[] hmacKey2 = HMACInputStream.getHMacKey( 0xffffffff_ffffffffL, hmacKey );

            final byte[] actualHeaderHMAC = calculateHMAC256( headerData, hmacKey2 );
            if ( ! Arrays.equals( expectedHeaderHMAC, actualHeaderHMAC ) ) {
                LOG.error( "HMAC error - expected: " + Misc.toHexString( expectedHeaderHMAC ) );
                LOG.error( "HMAC error - actual  : " + Misc.toHexString( actualHeaderHMAC ) );
                LOG.error( "HMAC error - length : expected=" + expectedHeaderHMAC.length + ", actual=" + actualHeaderHMAC.length );
                // hint: web application expects a BadPaddingException to be thrown if credentials are invalid
                throw new BadPaddingException( "Invalid credentials were provided, please try again.\nIf this reoccurs, then your database file may be corrupt." );
            }
        }
        buffer.setWriteCopyToTmpBuffer( false );

        if ( doNotDecrypt ) {
            return;
        }

        // Note on V4: The inner random stream cipher ID and key (to support process memory protection)
        // are now stored in the inner header instead of in the outer header.
        LOG.trace("XML payload starts at offset "+buffer.offset());

        // decrypt payload
        final byte[] encryptionIV = outerHeader.get( TLV.OuterHeaderType.ENCRYPTION_IV ).rawValue;

        if ( this.outerHeader.isV4() )
        {
            // Input streams get applied during read() in the following
            // order:
            // 1. read HMAC input stream, verify HMAC and strip HMAC and block length information from input
            // 2. Decrypt data
            // 3. Decompress data if necessary
            buffer.wrapInputStream( hmacKey, HMACInputStream::new );
            buffer.wrapInputStream( toWrap -> CipherStreamFactory.decryptInputStream( outerHeader.getOuterEncryptionAlgorithm(), finalKey.get(), encryptionIV, toWrap ) );
            if ( this.outerHeader.isCompressedPayload() ) {
                buffer.wrapInputStream( toWrap -> {
                    try {return new GZIPInputStream(toWrap);} catch( IOException e ) {throw new RuntimeException( e );}
                } );
            }
            this.innerHeader.read( buffer );
        }

        LOG.debug( "Inner encryption: " + getInnerEncryptionAlgorithm() );

        final byte[] encryptedPayload = buffer.readAll("payload");

        final byte[] decryptedPayload;
        if ( this.outerHeader.isV3() )
        {
            decryptedPayload = finalKey.get().decrypt( encryptedPayload, encryptionIV );
        } else {
            decryptedPayload = encryptedPayload;
        }

        if ( Constants.HEXDUMP_PAYLOAD )
        {
            LOG.trace("*** payload ***\n" + Serializer.hexdump(decryptedPayload));
        }

        // check that decryption worked correctly (<V4 only as >= V4 already uses HMACStream to verify the ciphertext)
        byte[] expected = null;
        if ( outerHeader.isV3() )
        {
            expected = outerHeader.get( TLV.OuterHeaderType.STREAM_START_BYTES ).rawValue;
            final byte[] actual = new byte[expected.length];
            System.arraycopy(decryptedPayload,0,actual,0,expected.length);

            for ( int i = 0 ; i < actual.length ; i++ ) {
                if ( expected[i] != actual[i] ) {
                    throw new RuntimeException("Bad master key, decryption failed at payload byte "+i+"," +
                        " expected 0x"+Integer.toHexString(expected[i])+
                        " but got 0x"+Integer.toHexString(actual[i]));
                }
            }
        }

        final Serializer payloadReader = new Serializer( new ByteArrayInputStream( decryptedPayload ) );
        byte[] xmlPayload;
        xmlPayload = payloadReader.readAll( "XML payload" );

        final ByteArrayInputStream bis = new ByteArrayInputStream(xmlPayload);
        if ( outerHeader.isV3() )
        {
            // skip magic at start of payload
            bis.readNBytes( expected.length );

            try ( Serializer helper = new Serializer( bis ) )
            {
                PayloadBlock lastBlock;
                do
                {
                    final int blockId = helper.readInt( "payload block ID" );
                    final byte[] blockHash = helper.readBytes( 32, "payload block hash" );
                    final int blockSize = helper.readInt( "payload block size" );
                    final byte[] blockData = blockSize > 0 ? helper.readBytes( blockSize, "payload block data" ) : new byte[0];

                    LOG.trace( "Got payload block of type 0x" + Integer.toHexString( blockId ) + ", length=" + blockSize
                        + ", hash=" + Misc.toHexString( blockHash ) );
                    lastBlock = new PayloadBlock( blockId, blockHash, blockData, outerHeader.isCompressedPayload() );
                    if ( !lastBlock.checksumOk() )
                    {
                        throw new RuntimeException( "Checksum failure on block " + lastBlock );
                    }
                    this.payloadBlocks.add( lastBlock );
                } while (lastBlock.blockId != PayloadBlock.BLOCK_ID_END_OF_PAYLOAD);
            }

            // validate header hash
            final byte[] actualHeaderHash = calculateHeaderHash();
            final byte[] expectedHeaderHash = new XmlPayloadView( this ).getHeaderHash();
            if ( !Arrays.equals( actualHeaderHash, expectedHeaderHash ) )
            {
                final String msg = "Header hash inside payload (" + Misc.toHexString( expectedHeaderHash ) + ") does " +
                    "not match actual header hash (" + Misc.toHexString( actualHeaderHash ) + ")";
                LOG.error( msg );
                throw new RuntimeException( msg );
            }
        } else {
            // create fake PayloadBlock entries so existing code (especially KDBX 3.1 <-> KDBX 4.x conversion) keeps working
            final PayloadBlock block = new PayloadBlock( PayloadBlock.BLOCK_ID_PAYLOAD, new byte[0], new byte[0], false );
            block.setData( bis.readAllBytes() );
            this.payloadBlocks.add( block );
            final PayloadBlock e = new PayloadBlock( PayloadBlock.BLOCK_ID_END_OF_PAYLOAD, new byte[0], new byte[0], false );
            e.setData( new byte [0] ); // necessary so block hash is correct
            this.payloadBlocks.add( e );

        }

        if ( Constants.DUMP_XML ) {
            LOG.info(XmlHelper.toString( getDecryptedXML()));
        }
    }

    public Optional<PayloadBlock> getBlock(int blockId) {
        return payloadBlocks.stream().filter(x->x.blockId == blockId).findFirst();
    }

    /**
     * Returns the XML payload with any protected payload values decrypted.
     *
     * @return
     * @see #getDecryptedXML(boolean)
     */
    public Document getDecryptedXML()
    {
        return getDecryptedXML(true);
    }

    public Document getDecryptedXML(boolean decryptProtectedPayloadValues)
    {
        final Optional<PayloadBlock> block = getBlock(PayloadBlock.BLOCK_ID_PAYLOAD);
        if ( block.isEmpty() ) {
            throw new IllegalStateException("No payload?");
        }
        final String xml = new String(block.get().getDecompressedPayload(), StandardCharsets.UTF_8);
        final Document document = XmlHelper.parse(xml);
        return decryptProtectedPayloadValues ? new InnerEncryptionProcessor(false).transform(document) : document;
    }

    public boolean isInnerEncryptionEnabled() {
        final FileHeader.InnerEncryptionAlgorithm algo = getInnerEncryptionAlgorithm();
        return ( algo != FileHeader.InnerEncryptionAlgorithm.NONE );
    }

    public Function<byte[],byte[]> createStreamCipher(boolean encrypt) {
        if ( ! isInnerEncryptionEnabled() ) {
            return in -> in;
        }
        final FileHeader.InnerEncryptionAlgorithm algo = getInnerEncryptionAlgorithm();
        final IStreamCipher cipher = switch(algo) {
            case SALSA20 -> new Salsa20();
            case CHACHA20 -> new ChaCha20();
            default -> throw new RuntimeException("Unsupported algorith "+algo);
        };
        if ( outerHeader.isV3() ) {
            cipher.init( outerHeader.get( TLV.OuterHeaderType.PROTECTED_STREAM_KEY).rawValue, encrypt );
        } else {
            cipher.init( innerHeader.get( TLV.InnerHeaderType.INNER_RANDOM_STREAM_KEY).rawValue, encrypt );
        }
        return cipher::process;
    }

    @Override
    public String toString() {
        return "Database("+resource+")";
    }

    public byte[] calculateHeaderHash() throws IOException
    {
        final ByteArrayOutputStream header = new ByteArrayOutputStream();
        try ( final Serializer headerBuffer = new Serializer(header) )
        {
            doWrite(Collections.emptyList(), headerBuffer, null, Logger.NOP,true);
        }
        return Hash.sha256(header.toByteArray());
    }

    private static byte[] hmacKey(TLV<TLV.OuterHeaderType> masterSeed, byte[] transformedMasterKey)
    {
        Validate.notNull( masterSeed, "masterSeed must not be null" );
        Validate.notNull( transformedMasterKey, "transformedKey must not be null" );

        if ( ! masterSeed.hasType( TLV.OuterHeaderType.MASTER_SEED ) ) {
            throw new IllegalArgumentException( "Wrong master seed header entry" );
        }
        if ( masterSeed.rawValue.length != 32 ) {
            throw new IllegalStateException( "Master seed should have 32 bytes" );
        }
        final Hash hmacKeyHash = Hash.sha512();
        hmacKeyHash.update(masterSeed.rawValue);
        hmacKeyHash.update(transformedMasterKey);
        return hmacKeyHash.finish( new byte[]{ 0x01 } ); // the weird 0x01 bytes comes from the original CS source...what's this for ?
    }

    private static byte[] calculateHMAC256(byte[] data, byte[] hmacKey) {
        return Hash.hmac256( hmacKey ).finish( data );
    }

    public class InnerEncryptionProcessor
    {
        private final Function<byte[],byte[]> cipher;
        private final boolean encrypt;
        private MemoryProtection memoryProtection;

        public InnerEncryptionProcessor(boolean encrypt) {
            this.cipher = createStreamCipher(encrypt);
            this.encrypt = encrypt;
        }

        public Document transform(Document input)
        {
            if (!isInnerEncryptionEnabled())
            {
                return input;
            }
            memoryProtection = new XmlPayloadView(Database.this).getMeta(input).memoryProtection;
            final Document result = XmlHelper.createDocumentBuilder().newDocument();
            decryptRecursively(result, input);
            return result;
        }

        private Node decryptRecursively(Document result, Node input)
        {
            Node resultNode;
            if (!(input instanceof Document))
            {
                resultNode = input.cloneNode(false);
                result.adoptNode(resultNode);
            }
            else
            {
                resultNode = result;
            }
            final NodeList childList = input.getChildNodes();
            for (int i = 0; i < childList.getLength(); i++)
            {
                Node x = maybeDecrypt(result, childList.item(i));
                final Node clone = x.cloneNode(true);
                result.adoptNode(clone);
                resultNode.appendChild(clone);
            }
            return resultNode;
        }

        private Node maybeDecrypt(Document resultDoc, Node valueNode)
        {
            if (valueNode.getNodeType() != Node.ELEMENT_NODE || ! "Value".equals(valueNode.getNodeName()))
            {
                return decryptRecursively(resultDoc, valueNode);
            }
            final String key = XmlHelper.directChild(valueNode.getParentNode(),"Key").getTextContent();
            final Optional<MemoryProtection.ProtectedItem> protectedItem = MemoryProtection.ProtectedItem.lookupByKeyName( key );
            final boolean supportsEncryption;
            final boolean isProtected;
            if ( protectedItem.isPresent() )
            {
                supportsEncryption = memoryProtection.isProtectionEnabled( protectedItem.get() );
                final String attrValue = ((Element) valueNode).getAttribute( XmlPayloadView.ATTR_IS_PROTECTED );
                isProtected = XmlPayloadView.boolFromString( attrValue );
            } else {
                supportsEncryption = false;
                isProtected = false;
            }
            if (encrypt == isProtected || (encrypt && ! supportsEncryption) )  // nothing to do...
            {
                return valueNode;
            }
            final Element result = resultDoc.createElement("Value");
            result.setAttribute( XmlPayloadView.ATTR_IS_PROTECTED, XmlPayloadView.boolToString(encrypt) );
            final String nodeValue = valueNode.getTextContent();
            result.setTextContent( isProtected ? decrypt(nodeValue) : encrypt(nodeValue));
            return result;
        }

        public String encrypt(String plainText)
        {
            return Base64.getEncoder().encodeToString(cipher.apply(plainText.getBytes(StandardCharsets.UTF_8)));
        }

        public String decrypt(String base64CipherText)
        {
            final byte[] binary = Base64.getDecoder().decode( base64CipherText );
            final byte[] decoded = cipher.apply( binary );
            return new String( decoded, StandardCharsets.UTF_8);
        }
    }

    public Version getAppVersion() {
        return outerHeader.appVersion;
    }

    public OuterEncryptionAlgorithm getOuterEncryptionAlgorithm() {
        return outerHeader.getOuterEncryptionAlgorithm();
    }

    public FileHeader.InnerEncryptionAlgorithm getInnerEncryptionAlgorithm() {

        final TLV<?> tlv;
        if ( outerHeader.isV3() )
        {
            tlv = outerHeader.get( TLV.OuterHeaderType.INNER_RANDOM_STREAM_ID );
        } else {
            tlv = innerHeader.getHeader( TLV.InnerHeaderType.INNER_RANDOM_STREAM_ID ).orElseThrow(() -> new RuntimeException("Inner header lacks RANDOM_STREAM_ID"));
        }
        final int typeId = tlv.numericValue().intValue();
        return FileHeader.InnerEncryptionAlgorithm.lookup( typeId ).orElseThrow(() -> new RuntimeException("Unhandled inner encryption type: " + typeId));
    }

    public long getTransformRounds()
    {
        /*
         * Up to KDBX 3.1, the number of rounds for AES-KDF was stored in the header field with ID 6 (TransformRounds),
         * and the seed for the transformation was stored in the header field with ID 5 (TransformSeed).
         * These two fields are obsolete now.
         * As of KDBX 4, key derivation function parameters are stored in the header field with ID 11 (KdfParameters).
         * The parameters are serialized as a VariantDictionary (with the KDF UUID being stored in '$UUID');
         * see the files KdfParameters.cs and VariantDictionary.cs.
         * For details on the parameters being used by AES-KDF and Argon2, see AesKdf.cs and Argon2Kdf.cs.
         */
        if ( outerHeader.isV3() )
        {
            final TLV<TLV.OuterHeaderType> transformRounds = outerHeader.get( TLV.OuterHeaderType.TRANSFORM_ROUNDS );
            return transformRounds.numericValue().longValue();
        }
        return switch( outerHeader.getKDF() ) {
            case AES_KDBX3, AES_KDBX4 -> outerHeader.getKdfParams().get( VariantDictionary.KDF_AES_ROUNDS ).getJavaValue( Long.class );
            case ARGON2D, ARGON2ID -> outerHeader.getKdfParams().get( VariantDictionary.KDF_ARGON2_ITERATIONS).getJavaValue( Long.class );
        };
    }

    public void setTransformRounds(long rounds) {
        if ( outerHeader.isV3() )
        {
            final TLV<TLV.OuterHeaderType> transformRounds = outerHeader.get( TLV.OuterHeaderType.TRANSFORM_ROUNDS );
            transformRounds.setLongValue( rounds );
            return;
        }
        final VariantDictionary.VariantDictionaryEntry entry = switch( outerHeader.getKDF() ) {
            case AES_KDBX3, AES_KDBX4 -> outerHeader.getKdfParams().get( VariantDictionary.KDF_AES_ROUNDS );
            case ARGON2D, ARGON2ID -> outerHeader.getKdfParams().get( VariantDictionary.KDF_ARGON2_ITERATIONS );
        };
        entry.setJavaValue( rounds, Long.class );
    }
}