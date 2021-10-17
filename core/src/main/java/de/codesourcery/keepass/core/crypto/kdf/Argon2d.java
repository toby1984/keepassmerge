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

import de.codesourcery.keepass.core.fileformat.VariantDictionary;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

public class Argon2d implements KeyDerivationFunction
{
    private Argon2BytesGenerator generator;

    @Override
    public void init(long rounds, byte[] seed, boolean isBenchmark, VariantDictionary params)
    {
        final byte[] salt = params.get( VariantDictionary.KDF_ARGON2_SALT ).getJavaValue( byte[].class );
        final int parallelism = params.get( VariantDictionary.KDF_ARGON2_PARALLELISM ).getJavaValue( Integer.class ); // uint32
        final long memInBytes = params.get( VariantDictionary.KDF_ARGON2_MEMORY_IN_BYTES ).getJavaValue( Long.class ); // uint64
        final long iterations = params.get( VariantDictionary.KDF_ARGON2_ITERATIONS ).getJavaValue( Long.class );
        final int version = params.get( VariantDictionary.KDF_ARGON2_VERSION).getJavaValue( Integer.class ); // uint32

        final Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_d);
        builder.withIterations((int) iterations );
        builder.withMemoryAsKB( (int) (memInBytes/1024) );
        builder.withParallelism( parallelism );
        builder.withSalt( salt );
        builder.withVersion(version);

        final Argon2Parameters parameters = builder.build();
        generator = new Argon2BytesGenerator();
        generator.init(parameters);
    }

    @Override
    public byte[] transform(byte[] input)
    {
        final byte[] output = new byte[32];
        generator.generateBytes(  input, output );
        return output;
    }
}
