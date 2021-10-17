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

import java.io.IOException;
import java.util.regex.Pattern;

public class Misc
{
    private static final Pattern BASE64_PATTERN = Pattern.compile( "^@(?=(.{4})*$)[A-Za-z0-9+/]*={0,2}$" );

    // BiFunction<InputStream,DATA,InputStream>
    public interface IOBiFunction<A,B,C> {
        C apply(A a, B b) throws IOException;
    }

    public interface IOFunction<A,B> {
        B apply(A value) throws IOException;
    }

    public interface ThrowingConsumer<A> {
        void consume(A a) throws IOException;
    }

    public interface ThrowingBiConsumer<A,B> {
        void consume(A a, B b) throws IOException;
    }

    public static boolean isBase64(String s)
    {
        if ( StringUtils.isNotBlank(s)) {
            return BASE64_PATTERN.matcher( s ).matches();
        }
        return false;
    }

    public static String toHexString(byte[] data) {
        return toHexString(data,"_");
    }

    public static byte[] fromHexString(String data) {
        return fromHexString( data, false );
    }

    public static byte[] fromHexString(String data, boolean ignoreNonHexCharacters)
    {
        final String s;
        if ( ignoreNonHexCharacters )
        {
            final StringBuilder stripped = new StringBuilder();
            for ( char c : data.toCharArray() )
            {
                final char lower = Character.toLowerCase( c );
                switch( lower )
                {
                    case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                        'a', 'b', 'c', 'd', 'e', 'f' -> stripped.append( lower );
                }
            }
            s = stripped.toString();
        } else {
            s = data;
        }
        if ( (s.length() & 1) != 0 ) {
            throw new IllegalArgumentException( "Input string needs to have an even number of characters" );
        }
        final byte[] result = new byte[s.length() / 2];
        for ( int i = 0 , ptr = 0, len = s.length() ; i < len ; ) {
            final char hi = s.charAt( i++ );
            final char lo = s.charAt( i++ );
            int v;
            if ( hi <= '9' ) {
                v = (hi - '0')<<4;
            } else {
                v = ( 10 + hi - 'a')<<4;
            }
            if ( lo <= '9' ) {
                v |= (lo - '0');
            } else {
                v |= (10 + lo - 'a');
            }
            result[ptr++] = (byte) v;
        }
        return result;
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

    public static byte[] concat(byte[] array1, byte[] array2)
    {
        final byte[] result = new byte[array1.length + array2.length];
        int ptr = 0;
        for ( final byte b : array1 )
        {
            result[ptr++] = b;
        }
        for ( final byte b : array2 )
        {
            result[ptr++] = b;
        }
        return result;
    }
}
