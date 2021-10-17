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

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class Serializer implements Closeable, AutoCloseable
{
    private int offset;
    private InputStream in;
    private OutputStream out;

    private boolean writeCopyToTmpBuffer; // whether each byte should also be written to the tmp buffer
    private ByteArrayOutputStream tmpBuffer = new ByteArrayOutputStream();

    public Serializer(InputStream in)
    {
        Validate.notNull(in, "in must not be null");
        this.in = needsBuffering(in) ? new BufferedInputStream(in) : in;
        this.out = null;
    }

    public void wrapInputStream(Misc.IOFunction<InputStream,InputStream> wrapperFunc) throws IOException {
        wrapInputStream( (Void) null, (in,data) -> wrapperFunc.apply(in) );
    }

    public <DATA> void wrapInputStream(DATA data, Misc.IOBiFunction<InputStream,DATA,InputStream> wrapperFunc) throws IOException {
        this.in = wrapperFunc.apply( this.in, data );
    }

    public void wrapOutputStream(Misc.IOFunction<OutputStream,OutputStream> wrapperFunc) throws IOException {
        wrapOutputStream( (Void) null, (in,data) -> wrapperFunc.apply(in) );
    }

    public <DATA> void wrapOutputStream(DATA data, Misc.IOBiFunction<OutputStream,DATA,OutputStream> wrapperFunc) throws IOException {
        this.out = wrapperFunc.apply( this.out, data );
    }

    private static boolean needsBuffering(InputStream in) {
        return !(in instanceof ByteArrayInputStream) && !(in instanceof BufferedInputStream);
    }

    private static boolean needsBuffering(OutputStream in) {
        return !(in instanceof ByteArrayOutputStream) && !(in instanceof BufferedOutputStream);
    }

    public void setWriteCopyToTmpBuffer(boolean writeCopyToTmpBuffer)
    {
        if ( this.writeCopyToTmpBuffer && ! writeCopyToTmpBuffer ) {
            this.tmpBuffer = new ByteArrayOutputStream();
        }
        this.writeCopyToTmpBuffer = writeCopyToTmpBuffer;
    }

    public byte[] getTmpBuffer() {
        if ( ! this.writeCopyToTmpBuffer ) {
            throw new IllegalStateException( "Copying to tmp buffer is disabled, reading from it makes no sense");
        }
        return tmpBuffer.toByteArray();
    }

    public Serializer(OutputStream out)
    {
        Validate.notNull(out, "out must not be null");
        this.in = null;
        this.out = needsBuffering(out) ? new BufferedOutputStream(out) : out;
    }

    public void flush() throws IOException
    {
        out.flush();
    }

    public byte[] readBytes(int count, String reason) throws IOException
    {
        final int offset = this.offset;
        try
        {
            final byte[] buffer = new byte[count];
            final int cnt = in.read(buffer);
            if ( cnt > 0 )
            {
                this.offset += cnt;
            }
            if ( cnt != count ) {
                throw new IOException("Premature end of file, expected "+count+" bytes but got only "+cnt);
            }
            if ( writeCopyToTmpBuffer ) {
                tmpBuffer.write( buffer );
            }
            return buffer;
        }
        catch(IOException e) {
            rethrow(e,reason,offset);
            throw new RuntimeException("Never reached"); // make compiler happy
        }
    }

    public long readLong(String reason) throws IOException
    {
        long low = readInt(reason);
        long high = readInt(reason);
        return ( (high & 0xffffffffL) <<32 ) | (low & 0xffffffffL);
    }

    public int readInt(String reason) throws IOException
    {
        int low = readShort(reason);
        int high = readShort(reason);
        return ((high & 0xffff)<<16) | (low & 0xffff);
    }

    public int readShort(String reason) throws IOException
    {
        int low = readByte(reason);
        int high = readByte(reason);
        return ((high & 0xff)<<8) | (low & 0xff);
    }

    public void writeBytes(byte[] data) throws IOException
    {
        writeBytes(data, 0, data.length);
    }

    public void writeBytes(byte[] data, int offset, int length) throws IOException
    {
        out.write(data, offset, length);
        this.offset += data.length;
        if ( writeCopyToTmpBuffer ) {
            tmpBuffer.write( data , offset, length );
        }
    }

    public void writeLong(long value) throws IOException
    {
        int low = (int) (value & 0xffffffffL);
        int high = (int) ((value >> 32 ) & 0xffffffffL);
        writeInt(low);
        writeInt(high);
    }

    public void writeInt(int value) throws IOException
    {
        int low = value & 0xffff;
        int high = (value >> 16 ) & 0xffff;
        writeShort(low);
        writeShort(high);
    }

    public void writeShort(int value) throws IOException
    {
        int low = value & 0xff;
        int high = (value >> 8 ) & 0xff;
        out.write(low);
        offset += 1;
        out.write(high);
        offset += 1;
        if ( writeCopyToTmpBuffer ) {
            tmpBuffer.write( low );
            tmpBuffer.write( high );
        }
    }

    public void writeByte(int value) throws IOException {
        out.write(value);
        if ( writeCopyToTmpBuffer )
        {
            tmpBuffer.write( value );
        }
        offset++;
    }

    public byte[] readAll(String reason) throws IOException
    {
        final int offset=this.offset;
        try
        {
            final byte[] result = in.readAllBytes();
            this.offset += result.length;
            if ( writeCopyToTmpBuffer ) {
                tmpBuffer.write( result );
            }
            return result;
        }
        catch(IOException e) {
            rethrow(e,reason,offset);
            throw new RuntimeException("Never reached"); // make compiler happy
        }
    }

    public int readByte(String reason) throws IOException
    {
        final int offset=this.offset;
        try
        {
            int result = in.read();
            if ( result == -1 ) {
                throw new EOFException("Premature end of file, expected to read one byte");
            }
            this.offset++;
            if ( writeCopyToTmpBuffer ) {
                tmpBuffer.write( result );
            }
            return result;
        }
        catch(IOException e) {
            rethrow(e,reason,offset);
            throw new RuntimeException("Never reached"); // make compiler happy
        }
    }

    private static void rethrow(IOException e, String reason, int offset) throws IOException
    {
        if ( e instanceof EOFException)
        {
            throw new EOFException("Premature end-of-file while while trying to read '" + reason + "' at offset "+offset+" : " + e.getMessage());
        }
        throw new IOException("Unexpected error while while trying to read '" + reason + "' at offset "+offset+" : " + e.getMessage(),e);

    }

    @Override
    public void close() throws IOException
    {
        if ( in != null ) {
            in.close();
        }
        if ( out != null ) {
            out.close();
        }
    }

    public static String hexdump(byte[] data)
    {
        final int bytesPerRow = 16;

        final StringBuffer result = new StringBuffer();
        final StringBuffer line = new StringBuffer();
        final StringBuffer ascii = new StringBuffer();
        int remaining = data.length;
        for ( int i = 0 ; i < remaining ; ) {

            ascii.setLength(0);
            line.setLength(0);
            line.append("0x").append(StringUtils.leftPad( Integer.toHexString(i),4,'0' ) );
            line.append(": ");
            for ( int j = 0 ; i < remaining && j < bytesPerRow ; j++ ) {
                int b = data[i++] & 0xff;
                if ( b >= 32 ) {
                    ascii.append( (char) b);
                } else {
                    ascii.append(".");
                }
                final String hex = StringUtils.leftPad( Integer.toHexString(b),2,'0' );
                line.append(hex).append(" ");
            }
            line.append(ascii.toString());
            if ( result.length() > 0 ) {
                result.append("\n");
            }
            result.append(line);
        }
        return result.toString();
    }

    public int offset() {
        return this.offset;
    }
}