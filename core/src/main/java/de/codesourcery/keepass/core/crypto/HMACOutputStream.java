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
package de.codesourcery.keepass.core.crypto;

import de.codesourcery.keepass.core.util.Endian;
import org.apache.commons.lang3.Validate;

import java.io.IOException;
import java.io.OutputStream;

public class HMACOutputStream extends OutputStream
{
    private final OutputStream wrappedStream;
    private final byte[] key;

    private static final int BLOCK_SIZE = 1024*1024;

    private static final class MyBuffer
    {
        private final byte[] buffer;

        private int bytesInBuffer;

        public MyBuffer(int size) {
            this.buffer = new byte[size];
        }

        public void append(byte[] data,int offset, int length)
        {
            System.arraycopy( data,offset,buffer,size(), length );
            bytesInBuffer += length;
        }

        public void append(byte value) {
            buffer[bytesInBuffer++] = value;
        }

        public void clear() {
            bytesInBuffer = 0;
        }

        public int spaceInBuffer() {
            return buffer.length - bytesInBuffer;
        }

        public int size() {
            return bytesInBuffer;
        }

        public boolean isFull() {
            return bytesInBuffer == buffer.length;
        }

        public boolean isEmpty() {
            return size() == 0;
        }
    }

    private final MyBuffer buffer = new MyBuffer(BLOCK_SIZE);
    private long blockIndex;
    private boolean isClosed;

    public HMACOutputStream(OutputStream toWrap, byte[] key) {
        Validate.notNull( toWrap, "toWrap must not be null" );
        Validate.isTrue(  key.length == 64, "Expected a 64-byte key but got only "+key.length+" bytes.");
        this.wrappedStream = toWrap;
        this.key = key;
    }

    @Override
    public void close() throws IOException
    {
        if ( isClosed ) {
            throw new IllegalStateException( "Output stream is already closed" );
        }
        try
        {
            isClosed = true;
            if ( !buffer.isEmpty() )
            {
                writeHashedBlock();
            }
            // write final block with size 0, this
            // is used by the HMACInputStream to detect the end of input
            // and distinguish it from a premature end of input condition.
            writeHashedBlock();
        } finally {
            wrappedStream.close();
        }
    }

    @Override
    public void write(byte[] data,int offset, int byteCountStillToWrite) throws IOException
    {
        while ( byteCountStillToWrite > 0 ) {
            final int bytesToCopy = Math.min( byteCountStillToWrite, buffer.spaceInBuffer() );
            buffer.append( data, offset, bytesToCopy );
            offset += bytesToCopy;
            byteCountStillToWrite -= bytesToCopy;
            if ( buffer.isFull() ) {
                writeHashedBlock();
            }
        }
    }

    private void writeHashedBlock() throws IOException
    {
        final byte[] bytesCountInBuffer = Endian.LITTLE.toIntBytes( buffer.size() ); // int32
        final Hash hasher = Hash.hmac256( getCurrentHMacKey() );
        hasher.update( Endian.LITTLE.toLongBytes( blockIndex ) ); // int64
        hasher.update( bytesCountInBuffer ); // int32
        final byte[] hash = hasher.finish( buffer.buffer, 0, buffer.size() );

        wrappedStream.write( hash );

        wrappedStream.write( Endian.LITTLE.toIntBytes( buffer.size() ) );
        if ( ! buffer.isEmpty() )
        {
            wrappedStream.write( buffer.buffer, 0, buffer.size() );
            buffer.clear();
        }
        blockIndex++;
    }

    public byte[] getCurrentHMacKey() {
        return HMACInputStream.getHMacKey( blockIndex, key );
    }

    @Override
    public void write(int b) throws IOException
    {
        buffer.append( (byte) b );
        if ( buffer.isFull() ) {
            writeHashedBlock();
        }
    }
}
