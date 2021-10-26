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

import de.codesourcery.keepass.core.crypto.OuterEncryptionAlgorithm;
import de.codesourcery.keepass.core.util.Serializer;
import org.apache.commons.lang3.Validate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;

/**
 * KeePassX database file header.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class FileHeader
{
    // This code is based on the brilliant analysis done here:
    // see https://gist.github.com/lgg/e6ccc6e212d18dd2ecd8a8c116fb1e45

    public enum Version
    {
        /*
         * File Signature 1 (the first field) will always have a value of 0x9AA2D903 .
         *
         * File Signature 2 (the second field) can have (for now) 3 different value, each value indicating the file format/version :
         *
         *     for .kdb files (KeePass 1.x file format) : 0xB54BFB65 ,
         *     for kdbx file of KeePass 2.x pre-release (alpha & beta) : 0xB54BFB66 ,
         *     for kdbx file of KeePass post-release : 0xB54BFB67 .
         *
         * After these 2 fields, .kdb and .kdbx differ totally : .kdb has fixed number of fields taking a fixed number of bytes in its header, while .kdbx has a TLV list of fields in its header.
         */
        KEEPASS1(0xB54BFB65) {
            public boolean isKeepass2() {
                return false;
            }
        },
        KEEPASS2_PRERELEASE(0xB54BFB66),
        KEEPASS2(0xB54BFB67);

        public final int magic;

        Version(int magic)
        {
            this.magic = magic;
        }

        public boolean isKeepass2() {
            return true;
        }

        public static Optional<FileHeader.Version> lookup(long magic) {
            return Arrays.stream(values()).filter(x->x.magic==magic).findFirst();
        }
    }

    // Type of encryption applied to each password contained in the payload XML
    public enum InnerEncryptionAlgorithm
    {
        NONE(0),
        ARC4_VARIANT(1),
        SALSA20(2),
        CHACHA20(3),
        ;

        public final int id;

        InnerEncryptionAlgorithm(int id)
        {
            this.id = id;
        }

        public static Optional<InnerEncryptionAlgorithm> lookup(int id) {
            return Arrays.stream(values()).filter(x->x.id == id ).findFirst();
        }
    }

    public FileHeader.Version headerVersion;
    public de.codesourcery.keepass.core.util.Version appVersion;

    // LinkedHashMap so we write out the headers in the same order we've read them
    public final Map<TLV.OuterHeaderType, TLV<TLV.OuterHeaderType>> headerEntries = new LinkedHashMap<>();

    public boolean isCompressedPayload() {
        final TLV<TLV.OuterHeaderType> flags = headerEntries.get( TLV.OuterHeaderType.COMPRESSION_FLAGS);
        return flags != null && (flags.numericValue().intValue() & 1 ) == 1;
    }

    public void add(TLV<TLV.OuterHeaderType> tlv)
    {
        Validate.notNull(tlv, "tlv must not be null");
        if ( headerEntries.containsKey(tlv.type)) {
            throw new IllegalArgumentException("Duplicate file header " + tlv.type + ", already got " + headerEntries.get(tlv.type));
        }
        headerEntries.put(tlv.type, tlv);
    }

    public TLV<TLV.OuterHeaderType> get(TLV.OuterHeaderType type) {
        Validate.notNull(type, "type must not be null");
        final TLV<TLV.OuterHeaderType> existing = headerEntries.get(type);
        if ( existing == null ) {
            throw new NoSuchElementException("File header has no entry of type "+type);
        }
        return existing;
    }

    public boolean isV3() {
        return appVersion.hasMajorVersion( 3 );
    }

    public boolean isV4() {
        return appVersion.hasMajorVersion( 4 );
    }

    public VariantDictionary getKdfParams()
    {
        if ( isV3() ) {
            throw new UnsupportedOperationException( "KDF parameters are only available in KDBX >= 4.0" );
        }
        final byte[] kdfParams = get( TLV.OuterHeaderType.KDF_PARAMETERS ).rawValue;
        try
        {
            return VariantDictionary.read( new Serializer( new ByteArrayInputStream( kdfParams ) ) );
        }
        catch( IOException e )
        {
            throw new RuntimeException( e );
        }
    }

    public KeyDerivationFunctionId getKDF()
    {
        if ( isV3() ) {
            return KeyDerivationFunctionId.AES_KDBX3;
        }
        return KeyDerivationFunctionId.lookup( getKdfParams().get( VariantDictionary.KDF_UUID ).getJavaValue( byte[].class ) );
    }

    /**
     * Returns the algorithm used for the "outer" encryption of the payload (sensitive information inside the "payload"
     * is protected with a different algorithm).
     *
     * @return
     */
    public OuterEncryptionAlgorithm getOuterEncryptionAlgorithm() {
        final TLV<TLV.OuterHeaderType> tlv = get( TLV.OuterHeaderType.CIPHER_ID );
        return OuterEncryptionAlgorithm.lookup( tlv.rawValue );
    }
}
