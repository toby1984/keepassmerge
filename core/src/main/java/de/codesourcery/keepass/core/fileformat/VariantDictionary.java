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

import de.codesourcery.keepass.core.util.Endian;
import de.codesourcery.keepass.core.util.Logger;
import de.codesourcery.keepass.core.util.LoggerFactory;
import de.codesourcery.keepass.core.util.Misc;
import de.codesourcery.keepass.core.util.Serializer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;

/**
 *  Up to KDBX 3.1, the number of rounds for AES-KDF was stored in the header field with ID 6 (TransformRounds), and the seed for the transformation was stored in the header field with ID 5 (TransformSeed). These two fields are obsolete now.
 *
 *  As of KDBX 4, key derivation function parameters are stored in the header field with ID 11 (KdfParameters). The parameters are serialized as a VariantDictionary (with the KDF UUID being stored in '$UUID'); see the files KdfParameters.cs and VariantDictionary.cs. For details on the parameters being used by AES-KDF and Argon2, see AesKdf.cs and Argon2Kdf.cs.
 *
 *  A VariantDictionary is a key-value dictionary (with the key being a string and the value being an object), which is serialized as follows:
 *
 *  [2 bytes] Version, as UInt16, little-endian, currently 0x0100 (version 1.0). The high byte is critical (i.e. the loading code should refuse to load the data if the high byte is too high), the low byte is informational (i.e. it can be ignored).
 *  [n items] n serialized items (see below).
 *  [1 byte] Null terminator byte.
 *
 *  Each of the n serialized items has the following form:
 *
 *  [1 byte] Value type, can be one of the following:
 *  0x04: UInt32.
 *  0x05: UInt64.
 *  0x08: Bool.
 *  0x0C: Int32.
 *  0x0D: Int64.
 *  0x18: String (UTF-8, without BOM, without null terminator).
 *  0x42: Byte array.
 *  [4 bytes] Length k of the key name in bytes, Int32, little-endian.
 *  [k bytes] Key name (string, UTF-8, without BOM, without null terminator).
 *  [4 bytes] Length v of the value in bytes, Int32, little-endian.
 *  [v bytes] Value. Integers are stored in little-endian encoding, and a Bool is one byte (false = 0, true = 1); the other types are clear.
 */
public class VariantDictionary extends HashMap<String,VariantDictionary.VariantDictionaryEntry>
{
    private static final Logger LOG = LoggerFactory.getLogger(VariantDictionary.class );

    /**
     * A little-endian system stores the least-significant byte at the smallest address.
     */
    public static final byte[] VERSION = new byte[]{0x00,0x01};

    // Holds the UUID of the KeyDerivationFunction (KDF) algorithm
    public static final String KDF_UUID = "$UUID";

    // AES params, see KeePass2.cpp
    public static final String KDF_AES_ROUNDS = "R";
    public static final String KDF_AES_SEED = "S";

    // Argon2 KDF parameters, see KeePass2.cpp
    public static final String KDF_ARGON2_SALT = "S";
    public static final String KDF_ARGON2_PARALLELISM = "P";
    public static final String KDF_ARGON2_MEMORY_IN_BYTES = "M";
    public static final String KDF_ARGON2_ITERATIONS = "I";
    public static final String KDF_ARGON2_VERSION = "V";

    public static final class VariantDictionaryEntry {

        public enum Type
        {
            /*
        End = 0,
        UInt32 = 0x04,
        UInt64 = 0x05,
        Bool = 0x08,
        Int32 = 0x0C,
        Int64 = 0x0D,
        String = 0x18,
        ByteArray = 0x42
             */
            END(0x00,Void.class),
            UINT_32(0x04,Integer.class), // TODO: Java has no unsigned types...
            UINT_64(0x05, Long.class), // TODO: Java has no unsigned types...
            BOOL(0x08,Boolean.class),
            INT_32(0x0C,Integer.class),
            INT_64(0x0D,Long.class),
            STRING(0x18,String.class), // (UTF-8 String, without BOM, without null terminator).
            BYTE_ARRAY(0x42,byte[].class);

            public final int id;
            public final Class<?> javaType;

            Type(int id,Class<?> javaType)
            {
                this.id = id;
                this.javaType = javaType;
            }

            public static Type lookup(int typeId)
            {
                return switch( typeId ) {
                    case 0x00 -> VariantDictionaryEntry.Type.END;
                    case 0x04 -> VariantDictionaryEntry.Type.UINT_32;
                    case 0x05 -> VariantDictionaryEntry.Type.UINT_64;
                    case 0x08 -> VariantDictionaryEntry.Type.BOOL;
                    case 0x0C -> VariantDictionaryEntry.Type.INT_32;
                    case 0x0D -> VariantDictionaryEntry.Type.INT_64;
                    case 0x18 -> VariantDictionaryEntry.Type.STRING;
                    case 0x42 -> VariantDictionaryEntry.Type.BYTE_ARRAY;
                    default -> throw new IllegalArgumentException( "Unknown VariantDictionary type ID 0x" + Integer.toHexString( typeId ) );
                };
            }

            public <T> byte[] fromJavaValue(T value,Class<T> evidence) {
                if ( value.getClass() != evidence ) {
                    throw new IllegalArgumentException("Invalid type "+value.getClass().getName()+" , expected exactly "+evidence.getName());
                }
                return switch( this ) {
                    case END -> new byte[0];
                    case STRING -> ((String) value).getBytes( StandardCharsets.UTF_8 );
                    case INT_32 -> Endian.LITTLE.toIntBytes( (Integer) value);
                    case INT_64 -> Endian.LITTLE.toLongBytes( (Long) value);
                    case UINT_32 -> Endian.LITTLE.toIntBytes( (Integer) value); // TODO: Java has no unsigned types...
                    case UINT_64 -> Endian.LITTLE.toLongBytes( (Long) value); // TODO: Java has no unsigned types...
                    case BOOL -> new byte[] { (byte) ((Boolean) value ? 1 : 0) };
                    case BYTE_ARRAY -> (byte[]) value;
                };
            }

            public <T> T toJavaValue(byte[] value,Class<T> evidence) throws IOException
            {
                if ( evidence != javaType ) {
                    throw new IllegalArgumentException( "Evidence mismatch, " + this + " produces " + javaType + " but caller expected " + evidence );
                }
                return (T) switch( this ) {
                    case END -> null;
                    case STRING -> new String( value, StandardCharsets.UTF_8 );
                    case INT_32 -> Endian.LITTLE.readInt(value);
                    case INT_64 -> Endian.LITTLE.readLong(value);
                    case UINT_32 -> Endian.LITTLE.readInt(value);
                    case UINT_64 -> Endian.LITTLE.readLong(value);
                    case BOOL -> {
                        if ( value.length != 1 ) {
                            throw new IllegalArgumentException( this + " requires a 1-byte value, got " + value.length + " bytes");
                        }
                        if ( value[0] == 0 ) {
                            yield Boolean.FALSE;
                        }
                        if ( value[0] == 1 ) {
                            yield Boolean.TRUE;
                        }
                        throw new IllegalArgumentException( this+" requires a 1-byte value of either 0 or 1" );
                    }
                    case BYTE_ARRAY -> value;
                };
            }
        }

        public Type type;
        public byte[] value;

        public VariantDictionaryEntry(Type type, byte[] value)
        {
            this.type = type;
            this.value = value;
        }

        public <T> T getJavaValue(Class<T> evidence)
        {
            try
            {
                return type.toJavaValue( this.value, evidence );
            }
            catch( IOException e )
            {
                throw new RuntimeException( e );
            }
        }

        public <T> void setJavaValue(T value, Class<T> evidence) {
            this.value = type.fromJavaValue(value, evidence );
        }
    }

    private final byte[] version;

    public VariantDictionary() {
        this.version = Arrays.copyOfRange( VERSION, 0, VERSION.length );
    }

    public <T> void put(String key, VariantDictionaryEntry.Type type, T value, Class<T> evidence)
    {
        final VariantDictionaryEntry entry = new VariantDictionaryEntry( type, new byte[0] );
        entry.setJavaValue( value, evidence);
        this.put( key , entry );
    }

    public static VariantDictionary read(Serializer serializer) throws IOException
    {
        final byte[] actualVersion = serializer.readBytes( 2, "VariantDictionary version" );
        if ( ! Arrays.equals( actualVersion, VERSION ) ) {
            throw new IOException( "Unsupported VariantDictionary version " + Misc.toHexString( actualVersion ) + " , expected " + Misc.toHexString( VERSION ) );
        }

        final VariantDictionary result = new VariantDictionary();
        while( true )
        {
             // [1 byte] Value type, can be one of the following:
            final int typeId = serializer.readByte( "VariantDictionary entry type ID" );
            final VariantDictionaryEntry.Type type = VariantDictionaryEntry.Type.lookup( typeId );

            // UNDOCUMENTED, reverse-engineered from code: Dictionary is terminated by 0x00 type ID
            if ( type == VariantDictionaryEntry.Type.END ) {
                break;
            }

            // [4 bytes] Length k of the key name in bytes, Int32, little-endian.
            final int keyLen = serializer.readInt( "VariantDictionary entry key length" );

            //  [k bytes] Key name (string, UTF-8, without BOM, without null terminator).
            final String key = new String( serializer.readBytes( keyLen, "VariantDictionary entry key" ), StandardCharsets.UTF_8 );

            // [4 bytes] Length v of the value in bytes, Int32, little-endian.
            final int valueLen = serializer.readInt( "VariantDictionary entry value length" );

            // [v bytes] Value. Integers are stored in little-endian encoding, and a Bool is one byte (false = 0, true = 1); the other types are clear.
            final byte[] value = serializer.readBytes( valueLen, "VariantDictionary entry value" );

            LOG.trace( "VariantDictionary.read(): type " + type + ", key='" + key + "', valueLen = " + value.length + ", value = " + Misc.toHexString( value ) );
            result.put( key , new VariantDictionaryEntry(type,value) );
        }
        return result;
    }
}
