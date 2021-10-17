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
import junit.framework.TestCase;

import java.io.IOException;

public class EndianTest extends TestCase
{
    public void testBigEndian() throws IOException
    {
        final byte[] data = bis( 0x01, 0x02, 0x03, 0x04,0x05,0x06,0x07,0x08 );
        assertEquals(0x0102030405060708L, Endian.BIG.readLong( data ));
        assertEquals(0x01020304, Endian.BIG.readInt( data ));
        assertHexEquals((short) 0x0102, Endian.BIG.readShort( data ));

        assertHexEquals( 0x0102, Endian.BIG.readShort( Endian.BIG.toShortBytes( 0x0102 ) ) );
        assertHexEquals( 0x01020304, Endian.BIG.readInt( Endian.BIG.toIntBytes( 0x01020304 ) ) );
        assertHexEquals( 0x0102030405060708L, Endian.BIG.readLong( Endian.BIG.toLongBytes( 0x0102030405060708L ) ) );
    }

    public void testLittleEndian()
    {
        final byte[] data = bis( 0x08,0x07,0x06,0x05,0x04, 0x03, 0x02, 0x01 );
        assertHexEquals(0x0102030405060708L, Endian.LITTLE.readLong( data ));
        assertHexEquals(0x05060708, Endian.LITTLE.readInt( data ));
        assertHexEquals(0x0708, Endian.LITTLE.readShort( data ));

        assertHexEquals( 0x0102, Endian.LITTLE.readShort( Endian.LITTLE.toShortBytes( 0x0102 ) ) );
        assertHexEquals( 0x01020304, Endian.LITTLE.readInt( Endian.LITTLE.toIntBytes( 0x01020304 ) ) );
        assertHexEquals( 0x0102030405060708L, Endian.LITTLE.readLong( Endian.LITTLE.toLongBytes( 0x0102030405060708L ) ) );
    }

    private void assertHexEquals(short expected, short actual) {
        if ( expected != actual ) {
            fail( "Expected 0x" + Integer.toHexString( expected & 0xffff ) + " but got 0x" + Integer.toHexString( actual & 0xffff ) );
        }
    }

    private void assertHexEquals(long expected, long actual) {
        if ( expected != actual ) {
            fail( "Expected 0x" + Long.toHexString( expected ) + " but got 0x" + Long.toHexString( actual ) );
        }
    }

    private void assertHexEquals(int expected, int actual) {
        if ( expected != actual ) {
            fail( "Expected 0x" + Integer.toHexString( expected ) + " but got 0x" + Integer.toHexString( actual ) );
        }
    }

    private byte[] bis(int... data) {

        final byte[] array = new byte[ data.length ];
        for ( int i = 0; i < data.length; i++ )
        {
            array[i] = (byte) data[i];
        }
        return array;
    }
}