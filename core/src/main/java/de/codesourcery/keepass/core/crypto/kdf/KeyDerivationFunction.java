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
package de.codesourcery.keepass.core.crypto.kdf;

import de.codesourcery.keepass.core.fileformat.KeyDerivationFunctionId;
import de.codesourcery.keepass.core.fileformat.VariantDictionary;
import org.apache.commons.lang3.Validate;

public interface KeyDerivationFunction
{
    void init(long rounds, byte[] seed, boolean isBenchmark, VariantDictionary params);

    byte[] transform(byte[] input);

    static KeyDerivationFunction create(KeyDerivationFunctionId id)
    {
        Validate.notNull( id, "id must not be null" );

        if ( id == KeyDerivationFunctionId.AES_KDBX3 )
        {
            return new Kdbx3Kdf();
        }
        if ( id == KeyDerivationFunctionId.ARGON2D )
        {
            return new Argon2d();
        }
        throw new UnsupportedOperationException( "KDF not implemented: " + id );
    }
}
