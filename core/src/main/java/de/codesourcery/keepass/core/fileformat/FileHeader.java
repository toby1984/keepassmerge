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

import org.apache.commons.lang3.Validate;

import java.util.*;

/**
 * KeePassX database file header.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class FileHeader
{
    // This code is actually based on the brilliant analysis done here:
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

    public enum OuterEncryptionAlgorithm {
        AES_CBC(new byte[] { 0x31, (byte) 0xc1, (byte) 0xf2, (byte) 0xe6, (byte) 0xbf,0x71,0x43,0x50, (byte) 0xbe,0x58,0x05,0x21,0x6a, (byte) 0xfc,0x5a, (byte) 0xff});

        private final byte[] expected;

        OuterEncryptionAlgorithm(byte[] expected)
        {
            this.expected = expected;
        }

        public final boolean matches(TypeLengthValue cipherId)
        {
            Validate.notNull(cipherId, "cipherId must not be null");
            if ( ! cipherId.hasType(TypeLengthValue.Type.CIPHER_ID ) ) {
                throw new IllegalStateException("Expected cipher ID TLV");
            }
            return Arrays.equals(this.expected, cipherId.rawValue);
        }
    }
    /*
     10) Depending on INNERRANDOMSTREAMID, set up the inner stream context.
      0 will mean all passwords in the XML will be in plain text,
      1 that they are encrypted with Arc4Variant (not detailed here)
      2 that they will be encrypted with Salsa20.
     */
    // Type of encryption applied to each password contained in the payload XML
    public enum InnerEncryptionAlgorithm
    {
        NONE(0),
        ARC4_VARIANT(1),
        SALSA20(2);
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
    public int appMinorVersion;
    public int appMajorVersion;

    // LinkedHashMap so we write out the headers in the same order we've read them
    public final Map<TypeLengthValue.Type,TypeLengthValue> headerEntries = new LinkedHashMap<>();

    public boolean isCompressedPayload() {
        final TypeLengthValue flags = headerEntries.get(TypeLengthValue.Type.COMPRESSION_FLAGS);
        return flags != null && (flags.numericValue().intValue() & 1 ) == 1;
    }

    public void add(TypeLengthValue tlv)
    {
        Validate.notNull(tlv, "tlv must not be null");
        if ( headerEntries.containsKey(tlv.type)) {
            throw new IllegalArgumentException("Duplicate file header " + tlv.type + ", already got " + headerEntries.get(tlv.type));
        }
        headerEntries.put(tlv.type, tlv);
    }

    public OuterEncryptionAlgorithm getOuterEncryptionAlgorithm() {
        final TypeLengthValue tlv = get(TypeLengthValue.Type.CIPHER_ID);
        for ( OuterEncryptionAlgorithm enc : OuterEncryptionAlgorithm.values() ) {
            if ( enc.matches(tlv) ) {
                return enc;
            }
        }
        throw new RuntimeException("Unsupported outer encryption cipher ID: " + TypeLengthValue.toHexString(tlv.rawValue));
    }

    public InnerEncryptionAlgorithm getInnerEncryptionAlgorithm() {
        final TypeLengthValue tlv = get(TypeLengthValue.Type.INNER_RANDOM_STREAM_ID);
        return InnerEncryptionAlgorithm.lookup( tlv.numericValue().intValue() )
                   .orElseThrow(() -> new RuntimeException("Unhandled inner encryption type 0x" +
                                                               TypeLengthValue.toHexString(tlv.rawValue)));
    }

    public TypeLengthValue get(TypeLengthValue.Type type) {
        Validate.notNull(type, "type must not be null");
        final TypeLengthValue existing = headerEntries.get(type);
        if ( existing == null ) {
            throw new NoSuchElementException("File header has no entry of type "+type);
        }
        return existing;
    }
}
