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

import de.codesourcery.keepass.core.fileformat.TypeLengthValue;
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

    private StreamCipher salsa;
    private ParametersWithIV params;

    public void init(TypeLengthValue streamKey) {

        Validate.notNull(streamKey, "streamKey must not be null");
        Validate.isTrue(streamKey.hasType(TypeLengthValue.Type.PROTECTED_STREAM_KEY));

        final byte[] key = Hash.sha256(streamKey.rawValue);
        final KeyParameter keyparam = new KeyParameter(key);
        params = new ParametersWithIV(keyparam, IV);
        salsa = new Salsa20Engine();
        salsa.init(false, params);
    }

    /*
10) Depending on INNERRANDOMSTREAMID, set up the inner stream context. 0 will mean all passwords in the XML will be in plain text, 1 that they are encrypted with Arc4Variant (not detailed here) and 2 that they will be encrypted with Salsa20.

11) Set up a Salsa20 context using key SHA256(PROTECTEDSTREAMKEY) and fixed IV [0xE8,0x30,0x09,0x4B,0x97,0x20,0x5D,0x2A].

12) Sequentially(!) look in the XML for "Value" nodes with the "Protected" attribute set to "True" (a suitable xpath might be "//Value[@Protected='True']").

13) Obtain their innerText and run it through base64_decode to obtain the encrypted password/data. Then, run it through salsa20 to obtain the cleartext data.

14) Optionally, check the header for integrity by taking sha256() hash of the whole header (up to, but excluding, the payload start bytes) and compare it with the base64_encode()d hash in the XML node <HeaderHash>(...)</HeaderHash>.
     */
    public byte[] process(byte[] input)
    {
        Validate.notNull(input, "cipherText must not be null");

        final byte[] output = new byte[input.length];
        salsa.processBytes(input, 0, input.length, output, 0);

        return output;
    }
}