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

import de.codesourcery.keepass.core.fileformat.TLV;

/**
 * Helper interface to abstract over the different symmetrical stream cipher implementations supported by KeePassX.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public interface IStreamCipher
{
    /**
     * Init cipher.
     *
     * @param streamKey key to use, taken from file header (see {@link TLV.OuterHeaderType#PROTECTED_STREAM_KEY})
     * @param encrypt whether to encrypt or decrypt
     */
    void init(byte[] streamKey, boolean encrypt);

    /**
     * Encrypt/decrypt data.
     *
     * @param input
     * @return
     */
    byte[] process(byte[] input);
}
