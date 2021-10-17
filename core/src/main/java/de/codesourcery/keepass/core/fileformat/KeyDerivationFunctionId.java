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

import de.codesourcery.keepass.core.util.Misc;

import java.util.Arrays;
import java.util.NoSuchElementException;

public enum KeyDerivationFunctionId
{
    AES_KDBX3( Misc.fromHexString( "c9d9f39a-628a-4460-bf74-0d08c18a4fea", true) ),
    AES_KDBX4( Misc.fromHexString("7c02bb82-79a7-4ac0-927d-114a00648238", true) ),
    ARGON2D( Misc.fromHexString("ef636ddf-8c29-444b-91f7-a9a403e30a0c", true) ),
    ARGON2ID( Misc.fromHexString("9e298b19-56db-4773-b23d-fc3ec6f0a1e6", true) );

    public final byte[] id;

    KeyDerivationFunctionId(byte[] id) {
        this.id = id;
    }

    public static KeyDerivationFunctionId lookup(byte[] id)
    {
        for ( final KeyDerivationFunctionId value : values() )
        {
            if ( Arrays.equals( value.id, id ) ) {
                return value;
            }
        }
        throw new NoSuchElementException( "Unknown key derivation function " + Misc.toHexString( id ) );
    }
}
