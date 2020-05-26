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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Hashing algorithm used throughout the KeePassX encryption key derivation process.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class Hash
{
    private final String algorithm;
    private final MessageDigest digest;

    private Hash(String algorithm)
    {
        this.algorithm = algorithm;
        try
        {
            this.digest = MessageDigest.getInstance(algorithm);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new RuntimeException("No "+algorithm+" digest?");
        }
    }

    public byte[] digest(byte[] input) {
        digest.reset();
        return digest.digest(input);
    }

    public static Hash sha256() {
        return new Hash("SHA-256");
    }

    public static byte[] sha256(byte[] data) {
        return sha256().digest(data);
    }
}
