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

import junit.framework.TestCase;
import org.junit.Assert;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Random;

public class HMACOutputStreamTest extends TestCase
{
    private static final byte[] SECRET_KEY = new byte[64];

    private static final Random RND = new Random( 0xdeadbeef );

    static {
        RND.nextBytes( SECRET_KEY );
    }

    private byte[] genTestData(int length) {
        final byte[] result = new byte[length];
        RND.nextBytes( result );
        return result;
    }

    public void testRoundTrip() throws IOException {
        doTestRoundTrip( 1024*1024 + 100 );
        doTestRoundTrip( 1234 );
        doTestRoundTrip( 10 );
        doTestRoundTrip( 1024*1024 );
    }
    private void doTestRoundTrip(int size) throws IOException
    {
        System.out.println( "Testing HmacOutputStream with size " + size );
        final byte[] expected = genTestData( size);
        final ByteArrayOutputStream bout = new ByteArrayOutputStream();
        try ( HMACOutputStream out = new HMACOutputStream( bout, SECRET_KEY ) )
        {
            out.write( expected );
        }
        final byte[] actual = new byte[expected.length];
        try ( HMACInputStream in = new HMACInputStream( new ByteArrayInputStream( bout.toByteArray() ), SECRET_KEY ) ) {
            assertEquals( expected.length, in.read( actual) );
        }
        Assert.assertArrayEquals( expected, actual );
    }
}