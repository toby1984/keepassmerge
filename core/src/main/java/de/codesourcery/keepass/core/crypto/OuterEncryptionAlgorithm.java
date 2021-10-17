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

import de.codesourcery.keepass.core.util.Misc;

import java.util.Arrays;
import java.util.NoSuchElementException;

/**
 * Algorithms used for the "outer" encryption of the payload.
 * Sensitive information inside the "payload"  is protected using a different set of algorithms.
 * @author tobias.gierke@code-sourcery.de
 */
public enum OuterEncryptionAlgorithm
{
    AES_128( Misc.fromHexString("61ab05a1-9464-41c3-8d74-3a563df8dd35", true) ),
    AES_256( Misc.fromHexString("31c1f2e6-bf71-4350-be58-05216afc5aff", true) ),
    TWOFISH( Misc.fromHexString("ad68f29f-576f-4bb9-a36a-d47af965346c", true ) ),
    CHACHA20( Misc.fromHexString("d6038a2b-8b6f-4cb5-a524-339a31dbb59a", true ) )
    ;

    public final byte[] id;

    OuterEncryptionAlgorithm(byte[] id) {
        this.id = id;
    }

    public static OuterEncryptionAlgorithm lookup(byte[] id)
    {
        for ( final OuterEncryptionAlgorithm value : values() )
        {
            if ( Arrays.equals( value.id, id ) ) {
                return value;
            }
        }
        throw new NoSuchElementException( "Unknown Cipher ID " + Misc.toHexString( id ) );
    }
}
