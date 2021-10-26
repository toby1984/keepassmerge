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

import de.codesourcery.keepass.core.util.Logger;
import de.codesourcery.keepass.core.util.LoggerFactory;
import org.apache.commons.lang3.Validate;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.Salsa20Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * SALSA20 stream cipher used by KeePassX to protect things inside the XML payload.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class Salsa20 implements IStreamCipher
{
    private static final Logger LOG = LoggerFactory.getLogger( Salsa20.class );

    // IV taken from KeePassX source code
    public static final byte[] IV = new byte[] {(byte) 0xE8,0x30,0x09,0x4B,(byte) 0x97,0x20,0x5D,0x2A};

    private StreamCipher cipher;

    public void init(byte[] streamKey, boolean encrypt) {

        Validate.isTrue(streamKey != null && streamKey.length > 0 , "streamKey must not be null or empty");

        final byte[] key = Hash.sha256(streamKey);
        final KeyParameter keyparam = new KeyParameter(key);
        final ParametersWithIV params = new ParametersWithIV( keyparam, IV );
        cipher = new Salsa20Engine();
        cipher.init(encrypt, params );
    }

    public byte[] process(byte[] input)
    {
        Validate.notNull(input, "cipherText must not be null");

        final byte[] output = new byte[input.length];
        cipher.processBytes(input, 0, input.length, output, 0);
        return output;
    }
}