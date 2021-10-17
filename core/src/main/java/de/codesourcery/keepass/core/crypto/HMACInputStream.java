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
import de.codesourcery.keepass.core.util.Logger;
import de.codesourcery.keepass.core.util.LoggerFactory;
import de.codesourcery.keepass.core.util.Misc;
import org.apache.commons.lang3.Validate;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

public class HMACInputStream extends InputStream implements AutoCloseable
{
    private static final Logger LOG = LoggerFactory.getLogger(HMACInputStream.class );

    private static final int BLOCK_SIZE = 1024*1024; // same as in KeePass source code

    private static final class MyBuffer
    {
        private byte[] buffer;
        private int bytesInBuffer;

        public MyBuffer(int size) {
            this.buffer = new byte[size];
        }

        public void assureSpace(int reqSize)
        {
            int requiredSpace = bytesInBuffer + reqSize;
            if ( requiredSpace > buffer.length ) {
                final byte[] tmp = new byte[ requiredSpace ];
                System.arraycopy( this.buffer,0,tmp,0,bytesInBuffer );
                buffer = tmp;
            }
        }

        public void clear() {
            this.bytesInBuffer = 0;
        }

        public int appendBytes(InputStream input, int bytesToRead) throws IOException
        {
            assureSpace( bytesToRead );
            final int bytesRead = input.read( buffer, bytesInBuffer, bytesToRead );
            if ( bytesRead > 0 ) {
                bytesInBuffer += bytesRead;
            }
            return bytesRead;
        }

        public void append(byte[] data) {
            System.arraycopy( data, 0, buffer, bytesInBuffer, data.length );
            bytesInBuffer+=data.length;
        }

        public int size() {
            return bytesInBuffer;
        }

        public boolean isEmpty() {
            return size() == 0;
        }
    }

    private static final Endian BYTE_ORDER = Endian.LITTLE;

    private final MyBuffer tmp_buffer;
    private InputStream wrappedStream;

    private ByteArrayInputStream currentInputStream;

    private final byte[] key;
    private int bufferPos = 0;
    private long blockIndex = 0;
    private boolean eof = false;

    public HMACInputStream(InputStream toWrap, byte[] key) {
        Validate.notNull( toWrap, "toWrap must not be null" );
        Validate.isTrue( key != null && key.length > 0 );
        this.wrappedStream = toWrap;
        this.key = key;
        this.tmp_buffer = new MyBuffer(BLOCK_SIZE);
    }

    @Override
    public void close() throws IOException
    {
        if ( wrappedStream != null ) {
            try {
                wrappedStream.close();
            } finally {
                wrappedStream = null;
            }
        }
    }

    @Override
    public int read() throws IOException
    {
        int result;
        if ( currentInputStream == null || (result = currentInputStream.read()) == -1 ) {
            final byte[] tmp = new byte[ BLOCK_SIZE ];
            int bytesRead = readData( tmp );
            if ( bytesRead < 1 ) {
                return -1;
            }
            currentInputStream = new ByteArrayInputStream( tmp );
            result = currentInputStream.read();
        }
        return result;
    }

    private int readData(byte[] data) throws IOException
    {
        if ( eof ) {
            return 0;
        }

        int bytesRemaining = data.length;
        int offset = 0;

        while (bytesRemaining > 0)
        {
            if ( bufferPos == tmp_buffer.size() )
            {
                if ( ! readHashedBlock() )
                {
                    return data.length - bytesRemaining;
                }
                bufferPos = 0;
            }
            final int bytesToCopy = Math.min( bytesRemaining, (tmp_buffer.size() - bufferPos));
            System.arraycopy( tmp_buffer.buffer, bufferPos,data,offset,bytesToCopy );

            offset += bytesToCopy;
            bufferPos += bytesToCopy;
            bytesRemaining -= bytesToCopy;
        }

        return data.length;
    }

    private boolean readHashedBlock() throws IOException
    {
        if ( eof ) {
            return false;
        }
        final byte[] hmac = new byte[32];
        if ( wrappedStream.read(hmac) != 32) {
            throw new IOException("Invalid HMAC size.");
        }

        final byte[] bytesInBlockLE = new byte[4];
        if ( wrappedStream.read( bytesInBlockLE ) != 4 ) {
            throw new IOException( "Invalid block size" );
        }
        final int bytesCountToRead = BYTE_ORDER.readInt( bytesInBlockLE );
        if (bytesCountToRead < 0) {
            throw new IOException("Invalid block size: "+bytesCountToRead);
        }

        tmp_buffer.clear();
        final int bytesRead = tmp_buffer.appendBytes( wrappedStream, bytesCountToRead );

        if ( bytesCountToRead > 0 && bytesRead != bytesCountToRead) {
            throw new EOFException( "Premature end of input, expected " + bytesCountToRead + " bytes but got only " + bytesRead );
        }

        final Hash hasher = Hash.hmac256( getCurrentHMacKey() );
        hasher.update( BYTE_ORDER.toLongBytes( blockIndex ) );
        hasher.update( bytesInBlockLE );
        final byte[] hasherResult = hasher.finish( tmp_buffer.buffer,0, tmp_buffer.bytesInBuffer);
        if ( ! Arrays.equals( hmac, hasherResult ) ) {
            LOG.error( "readHashedBlock(): [ "+bytesCountToRead+" bytes] expecting "+ Misc.toHexString( hmac )+", got: " );
            throw new IOException("HMAC check failed, data or hash value is corrupted");
        } else {
            LOG.debug( "readHashedBlock(): [ "+bytesCountToRead+" bytes] HMAC verified ok.");
        }

        blockIndex++;

        if (bytesCountToRead == 0) {
            eof = true;
            return false;
        }
        return true;
    }

    public boolean eof() {
        return eof;
    }

    /*
    QByteArray HmacBlockStream::getCurrentHmacKey() const
    {
        return getHmacKey(m_blockIndex, m_key);
    }
     */
    public byte[] getCurrentHMacKey() {
        return getHMacKey( blockIndex, key );
    }

    /*
    QByteArray HmacBlockStream::getHmacKey(quint64 blockIndex, const QByteArray& key)
{
    Q_ASSERT(key.size() == 64);
    QByteArray indexBytes = Endian::sizedIntToBytes<quint64>(blockIndex, ByteOrder);
    CryptoHash hasher(CryptoHash::Sha512);
    hasher.addData(indexBytes);
    hasher.addData(key);
    return hasher.result();
}
     */
    public static byte[] getHMacKey(long blockIndex, byte[] key)
    {
        Validate.isTrue(  key.length == 64, "Expected a 64-byte key but got only "+key.length+" bytes.");

        final byte[] indexBytes = Endian.LITTLE.toLongBytes(blockIndex);
        final Hash hasher = Hash.sha512();
        hasher.update(indexBytes);
        return hasher.finish(key);
    }
}