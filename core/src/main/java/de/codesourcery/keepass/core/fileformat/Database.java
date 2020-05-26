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
import de.codesourcery.keepass.core.crypto.*;
import de.codesourcery.keepass.core.datamodel.MemoryProtection;
import de.codesourcery.keepass.core.util.*;
import org.apache.commons.lang3.Validate;
import org.w3c.dom.*;

import javax.crypto.BadPaddingException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.function.Function;

public class Database
{
    private static Logger LOG = LoggerFactory.getLogger(Database.class );

    private static volatile boolean warmupDone;

    private static final int MAGIC = 0x9aa2d903;

    // This code is based on the brilliant analysis done here:
    // https://gist.githubusercontent.com/msmuenchen/9318327/raw/60d16b3faf5c680dee2be9d8b5cbfe877706f004/gistfile1.txt

    public IResource resource;
    public final FileHeader header = new FileHeader();
    public final List<PayloadBlock> payloadBlocks =new ArrayList<>();

    public Database load(List<Credential> credentials, IResource resource) throws IOException, BadPaddingException
    {
        LOG.info("Loading " + resource);
        try ( final Serializer buffer = new Serializer( resource.createInputStream() ) ) {
            this.resource = resource;
            return load(credentials,buffer);
        }
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
                for (int i = 0; i < 5000; i++)
                {
                    deriveMasterKey(credentials, 100, true);
                }
                warmupDone = true;
            }
            while(true)
            {
                final long iterationCount = header.get(TypeLengthValue.Type.TRANSFORM_ROUNDS).numericValue().longValue();
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
                float delta = minKeyDerivationTime.toMillis() - elapsedMillis;
                float slowIncThreshold = 0.1f * minKeyDerivationTime.toMillis();
                final float increment;
                if ( elapsedMillis < 5 || delta <= slowIncThreshold ) {
                    increment = (iterationCount*0.1f); // +10%
                    final String msg2 = "[incremental] Increasing no. of rounds by " + increment;
                    progressLogger.debug(msg2);
                    LOG.debug("doWrite(): " + msg2);
                } else {
                    /*
                     *         unknown iterations      current rounds * minKeyDerivationTime
                     *                              =  ------------------
                     *                                    elapsedTime
                     */
                    final float newValue =  ((iterationCount * minKeyDerivationTime.toMillis()) / elapsedMillis);
                    increment = newValue - iterationCount;
                    final String msg3 = "[non-incremental] Increasing no. of rounds by " + increment;
                    progressLogger.debug(msg3);
                    LOG.debug("doWrite(): " + msg3);
                }
                final long newIterationCount = iterationCount + (long) increment;
                if ( newIterationCount <= iterationCount ) {
                    throw new RuntimeException("Internal error, rounds counter must never be decreased here");
                }
                header.get(TypeLengthValue.Type.TRANSFORM_ROUNDS).setLongValue(newIterationCount);
            }
            // update header checksum inside XML payload block
            new XmlPayloadView(this).setHeaderHash(calculateHeaderHash());
        }

        // write magic
        buffer.writeInt(MAGIC);

        // write header version
        buffer.writeInt(header.headerVersion.magic);

        // write app version
        buffer.writeShort( header.appMinorVersion );
        buffer.writeShort( header.appMajorVersion );

        // write header entries
        for ( TypeLengthValue tlv : header.headerEntries.values() ) {
         tlv.write(buffer);
        }

        if ( doHeaderHashCalculationOnly ) {
            return;
        }

        // encrypt payload
        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try ( Serializer tmp = new Serializer(bos) )
        {
            bos.write(header.get(TypeLengthValue.Type.STREAM_START_BYTES).rawValue );
            for (PayloadBlock block : payloadBlocks)
            {
                block.write(tmp);
            }
        }
        final MasterKey masterKey = deriveMasterKey(credentials,false);
        final byte[] data = bos.toByteArray();
        final byte[] encPayload = masterKey.encrypt(data,header.get(TypeLengthValue.Type.ENCRYPTION_IV).rawValue);

        // write encrypted payload
        buffer.writeBytes(encPayload);
    }

    private MasterKey deriveMasterKey(List<Credential> credentials,boolean isBenchmark) {
        return deriveMasterKey(credentials,header.get(TypeLengthValue.Type.TRANSFORM_ROUNDS).numericValue().longValue(),isBenchmark);
    }

    private MasterKey deriveMasterKey(List<Credential> credentials, long rounds, boolean isBenchmark) {
        final CompositeKey compositeKey = CompositeKey.create(credentials);
        return MasterKey.create(
            compositeKey,
            header.get(TypeLengthValue.Type.TRANSFORM_SEED),
            header.get(TypeLengthValue.Type.MASTER_SEED),
            rounds,
            isBenchmark
        );
    }

    private Database load(List<Credential> credentials, Serializer buffer) throws IOException, BadPaddingException
    {
        Validate.notNull(credentials, "credentials must not be null");
        Validate.isTrue(!credentials.isEmpty(),"No credentials given?");
        Validate.notNull(resource, "resource must not be null");

        // magic
        int value = buffer.readInt("4 bytes signature");

        if ( value != MAGIC ) {
            throw new IOException("Not a valid KeePassX file (invalid magic 0x"+Integer.toHexString(value)+")");
        }

        // file header version
        value = buffer.readInt("4 bytes version");
        final Optional<FileHeader.Version> version = FileHeader.Version.lookup(value);
        if ( version.isEmpty() || ! version.get().isKeepass2() ) {
            throw new IOException("Unsupported file version 0x"+Integer.toHexString(value));
        }
        this.header.headerVersion = version.get();

        // app version
        this.header.appMinorVersion = buffer.readShort("app minor version");
        this.header.appMajorVersion = buffer.readShort("app major version");

        LOG.debug("App version "+this.header.appMajorVersion+"."+this.header.appMinorVersion);

        // read header entries
        while ( true ) {
            final TypeLengthValue tlv = TypeLengthValue.read(buffer);
            this.header.add(tlv);
            if ( tlv.hasType(TypeLengthValue.Type.END_OF_HEADER ) ) {
                break;
            }
        }

        final FileHeader.OuterEncryptionAlgorithm outerEnc = header.getOuterEncryptionAlgorithm();
        LOG.debug("Outer encryption: "+ outerEnc);
        LOG.debug("Inner encryption: "+header.getInnerEncryptionAlgorithm());

        LOG.trace("Payload starts at offset "+buffer.offset());

        // decrypt payload
        final MasterKey masterKey = deriveMasterKey(credentials,false);

        final byte[] data = buffer.readAll("payload");
        final byte[] payloadBuffer;
        payloadBuffer = masterKey.decrypt(data,header.get(TypeLengthValue.Type.ENCRYPTION_IV).rawValue);

        if ( Constants.HEXDUMP_PAYLOAD )
        {
            LOG.trace("*** payload ***\n" + Serializer.hexdump(payloadBuffer));
        }

        /*
6) Payload area (from end of header until file end).
6.1) BYTE[len(STREAMSTARTBYTES)] BYTE string. When payload area is successfully decrypted, this area MUST equal STREAMSTARTBYTES. Normally the length is 32 bytes.
6.2) There are at least 2 payload blocks in the file, each is laid out [LE DWORD dwBlockId, BYTE[32] sHash, LE DWORD dwBlockSize, BYTE[dwBlockSize] bData].

dwBlockSize=0 and sHash=\0\0\...\0 (32x \0) signal the final block, this is the last data in the file.
         */

        // verify that decryption worked correctly
        final byte[] expected = header.get(TypeLengthValue.Type.STREAM_START_BYTES).rawValue;
        final byte[] actual = new byte[expected.length];
        System.arraycopy(payloadBuffer,0,actual,0,expected.length);

        for ( int i = 0 ; i < actual.length ; i++ ) {
            if ( expected[i] != actual[i] ) {
                throw new RuntimeException("Bad master key, decryption failed at payload byte "+i+"," +
                                               " expected 0x"+Integer.toHexString(expected[i])+
                                               " but got 0x"+Integer.toHexString(actual[i]));
            }
        }

        // decrypt payload area
        /*
6) Payload area (from end of header until file end).
6.1) BYTE[len(STREAMSTARTBYTES)] BYTE string. When payload area is successfully decrypted, this area MUST equal STREAMSTARTBYTES. Normally the length is 32 bytes.
6.2) There are at least 2 payload blocks in the file, each is laid out [LE DWORD dwBlockId, BYTE[32] sHash, LE DWORD dwBlockSize, BYTE[dwBlockSize] bData].

dwBlockSize=0 and sHash=\0\0\...\0 (32x \0) signal the final block, this is the last data in the file.

.....

9) If COMPRESSIONFLAGS = 1, run bData through gzdecode() to obtain the plain Keepass XML file; if COMPRESSIONFLAGS is 0, it is already in bData.

10) Depending on INNERRANDOMSTREAMID, set up the inner stream context. 0 will mean all passwords in the XML will be in plain text, 1 that they are encrypted with Arc4Variant (not detailed here) and 2 that they will be encrypted with Salsa20.

11) Set up a Salsa20 context using key PROTECTEDSTREAMKEY and fixed IV [0xE8,0x30,0x09,0x4B,0x97,0x20,0x5D,0x2A].

12) Sequentially(!) look in the XML for "Value" nodes with the "Protected" attribute set to "True" (a suitable xpath might be "//Value[@Protected='True']").

13) Obtain their innerText and run it through base64_decode to obtain the encrypted password/data. Then, run it through salsa20 to obtain the cleartext data.

14) Optionally, check the header for integrity by taking sha256() hash of the whole header (up to, but excluding, the payload start bytes) and compare it with the base64_encode()d hash in the XML node <HeaderHash>(...)</HeaderHash>.
         */
        final ByteArrayInputStream bis = new ByteArrayInputStream(payloadBuffer);
        // skip magic at start of payload
        bis.readNBytes(expected.length);

        try ( Serializer helper = new Serializer(bis))
        {
            PayloadBlock lastBlock = null;
            do
            {
                final int blockId = helper.readInt("payload block ID");
                final byte[] blockHash = helper.readBytes(32, "payload block hash");
                final int blockSize = helper.readInt("payload block size");
                final byte[] blockData = blockSize > 0 ? helper.readBytes(blockSize, "payload block data") : new byte[0];

                LOG.trace("Got payload block of type 0x" + Integer.toHexString(blockId) + ", length=" + blockSize
                                       + ", hash=" + TypeLengthValue.toHexString(blockHash));
                lastBlock = new PayloadBlock(blockId, blockHash, blockData, header.isCompressedPayload());
                if ( ! lastBlock.checksumOk() ) {
                    throw new RuntimeException("Checksum failure on block "+lastBlock);
                }
                this.payloadBlocks.add(lastBlock);
            } while ( lastBlock.blockId != PayloadBlock.BLOCK_ID_END_OF_PAYLOAD );
        }

        // validate header hash
        final byte[] actualHeaderHash = calculateHeaderHash();
        final byte[] expectedHeaderHash = new XmlPayloadView(this).getHeaderHash();
        if ( ! Arrays.equals(actualHeaderHash, expectedHeaderHash ) ) {
            final String msg = "Header hash inside payload (" + TypeLengthValue.toHexString(expectedHeaderHash) + ") does " +
                                   "not match actual header hash (" + TypeLengthValue.toHexString(actualHeaderHash) + ")";
            LOG.error(msg);
            throw new RuntimeException(msg);
        }

        if ( Constants.DUMP_XML ) {
            LOG.trace(XmlHelper.toString(getDecryptedXML()));
        }
        return this;
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
        final FileHeader.InnerEncryptionAlgorithm algo = header.getInnerEncryptionAlgorithm();
        return ( algo != FileHeader.InnerEncryptionAlgorithm.NONE );
    }

    public Function<byte[],byte[]> createStreamCipher() {
        if ( ! isInnerEncryptionEnabled() ) {
            return in -> in;
        }
        final FileHeader.InnerEncryptionAlgorithm algo = header.getInnerEncryptionAlgorithm();
        // TODO: Add support for other algorithms
        final IStreamCipher cipher = switch(algo) {
            case SALSA20 -> new Salsa20();
            default -> throw new RuntimeException("Unsupported algorith "+algo);
        };
        cipher.init(header.get(TypeLengthValue.Type.PROTECTED_STREAM_KEY));
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

    public class InnerEncryptionProcessor
    {
        private final Function<byte[],byte[]> cipher;
        private final boolean encrypt;
        private MemoryProtection memoryProtection;

        public InnerEncryptionProcessor(boolean encrypt) {
            this.cipher = createStreamCipher();
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
            if (valueNode.getNodeType() != Node.ELEMENT_NODE || !"Value".equals(valueNode.getNodeName()))
            {
                return decryptRecursively(resultDoc, valueNode);
            }
            final String key = XmlHelper.directChild(valueNode.getParentNode(),"Key").getTextContent();
            final boolean supportsEncryption =
                memoryProtection.isProtectionEnabled( MemoryProtection.ProtectedItem.lookupByKeyName(key) );
            final String attrValue = ((Element) valueNode).getAttribute( XmlPayloadView.ATTR_IS_PROTECTED );
            final boolean isProtected = XmlPayloadView.boolFromString(attrValue);
            if (encrypt == isProtected || (encrypt && ! supportsEncryption) )  // nothing to do...
            {
                return valueNode;
            }
            final Element result = resultDoc.createElement("Value");
            result.setAttribute( XmlPayloadView.ATTR_IS_PROTECTED, XmlPayloadView.boolToString(encrypt) );
            final String nodeValue = valueNode.getTextContent();
            result.setTextContent(isProtected ? transform(nodeValue) : encryptInner(nodeValue));
            return result;
        }

        public String encryptInner(String plainText)
        {
            return Base64.getEncoder().encodeToString(cipher.apply(plainText.getBytes(StandardCharsets.UTF_8)));
        }

        public String transform(String base64CipherText)
        {
            return new String(cipher.apply(Base64.getDecoder().decode(base64CipherText)), StandardCharsets.UTF_8);
        }
    }
}