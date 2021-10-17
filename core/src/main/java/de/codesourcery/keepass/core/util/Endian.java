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
package de.codesourcery.keepass.core.util;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

public enum Endian
{
    BIG {
        @Override
        public int read(InputStream in, byte[] destination, int offset, int count) throws IOException
        {
            // Java's native byte order is Big-Endian, nothing to be done here
            return in.read( destination, offset, count );
        }

        @Override
        public void toBigEndian(byte[] data, int bytesRead)
        {
            // nothing to do here
        }

        public byte[] toShortBytes(int value) {
            final byte hi = (byte) ((value >> 8) & 0xff);
            final byte lo = (byte) (value & 0xff);
            return new byte[] { hi, lo };
        }

        public byte[] toIntBytes(int value) {
            final byte b1 = (byte) ((value >> 24) & 0xff);
            final byte b2 = (byte) ((value >> 16) & 0xff);
            final byte b3 = (byte) ((value >>  8) & 0xff);
            final byte b4 = (byte) (value & 0xff);
            return new byte[]{b1, b2, b3, b4};
        }

        public byte[] toLongBytes(long value) {
            final byte b1 = (byte) ((value >> 56) & 0xff);
            final byte b2 = (byte) ((value >> 48) & 0xff);
            final byte b3 = (byte) ((value >> 40) & 0xff);
            final byte b4 = (byte) ((value >> 32) & 0xff);
            final byte b5 = (byte) ((value >> 24) & 0xff);
            final byte b6 = (byte) ((value >> 16) & 0xff);
            final byte b7 = (byte) ((value >> 8) & 0xff);
            final byte b8 = (byte) (value & 0xff);
            return new byte[] { b1,b2, b3, b4, b5, b6, b7, b8 };
        }

        public short readShort(byte[] data, int offset) {
            int hi = data[offset] & 0xff;
            int lo = data[offset+1] & 0xff;
            return (short) (hi << 8 | lo);
        }

        public int readInt(byte[] data, int offset) {
            int hi = readShort(data,offset) & 0xffff;
            int lo = readShort(data,offset+2) & 0xffff;
            return (hi << 16 | lo);
        }
        public long readLong(byte[] data, int offset) {
            long hi = readInt(data,offset) & 0xffffffff;
            long lo = readInt(data,offset+4) & 0xffffffff;
            return (hi << 32 | lo);
        }
    },
    LITTLE {
        @Override
        public int read(InputStream in, byte[] destination, int offset, int count) throws IOException
        {
            final int bytesRead = in.read(destination,offset,count);
            for ( int head = 0, tail = bytesRead-1 ; head < tail ; head++, tail-- )
            {
                final byte tmp = destination[head];
                destination[head] = destination[tail];
                destination[tail] = tmp;
            }
            return bytesRead;
        }

        @Override
        public void toBigEndian(byte[] data, int bytesRead)
        {
            for ( int head = 0, tail = bytesRead-1 ; head < tail ; head++, tail-- )
            {
                final byte tmp = data[head];
                data[head] = data[tail];
                data[tail] = tmp;
            }
        }

        public short readShort(byte[] data, int offset) {
            int hi = data[offset+1] & 0xff;
            int lo = data[offset] & 0xff;
            return (short) (hi << 8 | lo);
        }

        public int readInt(byte[] data, int offset) {
            int hi = readShort(data,offset+2) & 0xffff;
            int lo = readShort(data,offset) & 0xffff;
            return (hi << 16 | lo);
        }

        public long readLong(byte[] data, int offset) {
            long hi = readInt(data,offset+4) & 0xffffffffL;
            long lo = readInt(data,offset) & 0xffffffffL;
            return (hi << 32 | lo);
        }

        public byte[] toShortBytes(int value) {
            final byte hi = (byte) ((value >> 8) & 0xff);
            final byte lo = (byte) (value & 0xff);
            return new byte[] { lo, hi };
        }

        public byte[] toIntBytes(int value) {
            final byte b4 = (byte) ((value >> 24) & 0xff);
            final byte b3 = (byte) ((value >> 16) & 0xff);
            final byte b2 = (byte) ((value >>  8) & 0xff);
            final byte b1 = (byte) (value & 0xff);
            return new byte[]{b1, b2, b3, b4};
        }

        public byte[] toLongBytes(long value) {
            final byte b1 = (byte) (value & 0xff);
            final byte b2 = (byte) ((value >> 8) & 0xff);
            final byte b3 = (byte) ((value >> 16) & 0xff);
            final byte b4 = (byte) ((value >> 24) & 0xff);
            final byte b5 = (byte) ((value >> 32) & 0xff);
            final byte b6 = (byte) ((value >> 40) & 0xff);
            final byte b7 = (byte) ((value >> 48) & 0xff);
            final byte b8 = (byte) ((value >> 56) & 0xff);
            return new byte[] { b1, b2, b3, b4, b5, b6, b7, b8 };
        }
    };

    public abstract void toBigEndian(byte[] data, int bytesRead);

    public void toBigEndian(byte[] data) {
        toBigEndian( data, data.length );
    }

    public abstract int read(InputStream in, byte[] destination, int offset, int count) throws IOException;

    public abstract short readShort(byte[] data, int offset);

    public short readShort(byte[] data) {
        return readShort( data, 0 );
    }

    public abstract int readInt(byte[] data, int offset);

    public int readInt(byte[] data) {
        return readInt( data, 0 );
    }

    public abstract long readLong(byte[] data, int offset);

    public long readLong(byte[] data) {
        return readLong( data, 0 );
    }

    public int read(InputStream in, byte[] destination) throws IOException {
        return read(in,destination,0,destination.length);
    }

    private byte[] readSafely(InputStream in, int count, String error) throws IOException {

        final byte[] destination = new byte[count];
        final int read = in.read( destination, 0, count );
        if ( read < count ) {
            throw new EOFException("Premature end of input while reading '"+error+"', expected "+count+" bytes but got "+read);
        }
        return destination;
    }

    public short readShort(InputStream in, String error) throws IOException {
        return readShort( readSafely( in, 2, error ), 0 );
    }

    public int readInt(InputStream in, String error) throws IOException {
        final short hi = readShort( in, error );
        final short lo = readShort( in, error );
        return (hi & 0xffff) << 16 | ( lo & 0xffff );
    }

    public long readLong(InputStream in, String error) throws IOException {
        final long hi = readInt( in, error ) & 0xffffffffL;
        final long lo = readInt( in, error ) & 0xffffffffL;
        return (hi << 32) | lo;
    }

    public abstract byte[] toShortBytes(int value);

    public abstract byte[] toIntBytes(int value);

    public abstract byte[] toLongBytes(long value);
}