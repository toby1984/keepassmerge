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

import org.apache.commons.lang3.Validate;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.util.Arrays;

public class ChaCha20 implements IStreamCipher
{
    private StreamCipher cipher;

    @Override
    public void init(byte[] streamKey, boolean encrypt)
    {
        Validate.isTrue(streamKey != null && streamKey.length > 0 , "streamKey must not be null or empty");

        final byte[] generated = Hash.sha512().finish( streamKey );
        final byte[] actualKey = Arrays.copyOfRange( generated, 0, 32 );
        final byte[] iv = Arrays.copyOfRange( generated, 32, 32+12 );

        final KeyParameter keyparam = new KeyParameter(actualKey);
        final ParametersWithIV params = new ParametersWithIV( keyparam, iv );
        final ChaCha7539Engine tmp = new ChaCha7539Engine();
        tmp.init(true, params ); // cipher is symmetrical, encrypt/decrypt does not matter
        cipher = tmp;
    }

    @Override
    public byte[] process(byte[] input)
    {
        Validate.notNull(input, "cipherText must not be null");

        final byte[] output = new byte[input.length];
        cipher.processBytes(input, 0, input.length, output, 0);
        return output;
    }
}
