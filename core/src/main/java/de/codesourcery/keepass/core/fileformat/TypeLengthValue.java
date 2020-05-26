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

import de.codesourcery.keepass.core.util.Serializer;
import org.apache.commons.lang3.Validate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.*;

/**
 * Represents a fixed-length entry in the KeePassX file header.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class TypeLengthValue
{
    /*
     * .kdbx header’s fields are a Type-Length-Value list.
     * The Type takes 1 byte, the Length takes 2 bytes, and the Value takes Length bytes.
     */
    public enum Type {
        // 5.1) bId=0: END entry, no more header entries after this
        END_OF_HEADER(0),
        // bId= 1: COMMENT entry, unknown
        COMMENT(1),
        // bId= 2: CIPHERID, bData="31c1f2e6bf714350be5805216afc5aff" => outer encryption AES256, currently no others supported
        CIPHER_ID(2),
        // bId= 3: COMPRESSIONFLAGS, LE DWORD. 0=payload not compressed, 1=payload compressed with GZip
        COMPRESSION_FLAGS(3),
        // bId= 4: MASTERSEED, 32 BYTEs string. See further down for usage/purpose. Length MUST be checked.
        MASTER_SEED(4),
        // bId= 5: TRANSFORMSEED, variable length BYTE string. See further down for usage/purpose.
        TRANSFORM_SEED(5),
        // bId= 6: TRANSFORMROUNDS, LE QWORD. See further down for usage/purpose.
        TRANSFORM_ROUNDS(6),
        // bId= 7: ENCRYPTIONIV, variable length BYTE string. See further down for usage/purpose.
        ENCRYPTION_IV(7),
        // bId= 8: PROTECTEDSTREAMKEY, variable length BYTE string. See further down for usage/purpose.
        PROTECTED_STREAM_KEY(8),
        // bId= 9: STREAMSTARTBYTES, variable length BYTE string. See further down for usage/purpose.
        STREAM_START_BYTES(9),
        // bId=10: INNERRANDOMSTREAMID, LE DWORD. Inner stream encryption type, 0=>none, 1=>Arc4Variant, 2=>Salsa20
        INNER_RANDOM_STREAM_ID(10);

        private final int id;

        Type(int id)
        {
            this.id = id;
        }

        public static Optional<Type> lookup(int value) {
            return Arrays.stream(values()).filter(x->x.id==value).findFirst();
        }
    }

    public Type type;
    public byte[] rawValue;

    public TypeLengthValue(Type type, byte[] rawValue)
    {
        Validate.notNull(type, "type must not be null");
        Validate.notNull(rawValue, "rawValue must not be null");
        this.type = type;
        this.rawValue = rawValue;
    }

    public boolean hasType(Type t)
    {
        return t.equals( this.type);
    }

    @Override
    public String toString()
    {
        return switch(length())
        {
            case 1, 2, 4, 8 -> "type=" + type + ", length=" + length() + ", value=" + numericValue() + ", rawValue=" + toHexString(rawValue);
            default -> "type=" + type + ", length=" + length() + ", rawValue=" + toHexString(rawValue);
        };
    }

    public int length() {
        return rawValue.length;
    }

    public Number numericValue()
    {
        try
        {
            return switch (length())
                       {
                           case 1 -> readHelper().readByte("byte");
                           case 2 -> readHelper().readShort("short");
                           case 4 -> readHelper().readInt("int");
                           case 8 -> readHelper().readLong("long");
                           default -> throw new UnsupportedOperationException("Cannot turn " + length() + "-byte value into Number");
                       };
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }
    }

    public void setByteValue(int value) {
        updateValue(ser -> ser.writeByte(value) );
    }

    public void setShortValue(int value) {
        updateValue(ser -> ser.writeShort(value) );
    }

    public void setIntValue(int value) {
        updateValue(ser -> ser.writeInt(value) );
    }

    public void setLongValue(long value) {
        updateValue(ser -> ser.writeLong(value) );
    }

    private interface IOOperation {
        void perform(Serializer s) throws IOException;
    }

    private void updateValue(IOOperation s)
    {
        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try ( Serializer ser = new Serializer(bos) ) {
            s.perform(ser);
            rawValue = bos.toByteArray();
        } catch(IOException e) {
            // cannot possibly happen, we're writing to a byte array
            throw new RuntimeException(e);
        }
    }

    private Serializer readHelper() {
        return new Serializer(new ByteArrayInputStream(this.rawValue));
    }

    public static String toHexString(byte[] data) {
        return toHexString(data,"_");
    }

    public static String toHexString(byte[] data, String separator)
    {
        if ( data == null || data.length == 0) {
            return "<empty>";
        }
        final StringBuilder buffer = new StringBuilder("0x");
        final char[] chars = "0123456789abcdef".toCharArray();
        for ( int i = 0 ; i < data.length ; i++ ) {
            int value = data[i] & 0xff;
            char hi = chars[ (value & 0xf0)>>>4];
            char lo = chars[  value & 0x0f     ];
            buffer.append(hi).append(lo);
            if ( (i+1) < data.length ) {
                buffer.append(separator);
            }
        }
        return buffer.toString();
    }

    public void write(Serializer helper) throws IOException {
        helper.writeByte(this.type.id);
        helper.writeShort(this.rawValue.length);
        if ( this.rawValue.length > 0) {
            helper.writeBytes(this.rawValue);
        }
    }

    public static TypeLengthValue read(Serializer helper) throws IOException
    {
        /*
         * The Type takes 1 byte, the Length takes 2 bytes, and the Value takes Length bytes.
         */
        final int typeId = helper.readByte("1 byte header entry type");
        final Optional<Type> type = Type.lookup(typeId);
        if ( type.isEmpty() ) {
            throw new IOException("Unknown header entry type 0x"+Integer.toHexString(typeId));
        }
        final int length = helper.readShort("2 byte header entry length");
        final byte[] data;
        if ( length > 0 ) {
            data = helper.readBytes(length,length+" bytes of data for header entry "+type.get());
        } else {
            data = new byte[0];
        }
        return new TypeLengthValue(type.get(), data );
    }
}
