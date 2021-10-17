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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Derived KeePassX 'master key' that is used to encrypt/decrypt the actual payload.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class MasterKey
{
    private static final Logger LOG = LoggerFactory.getLogger( MasterKey.class );

    public final OuterEncryptionAlgorithm cipher;
    public final byte[] data;
    public final byte[] transformedKey;

    public MasterKey(OuterEncryptionAlgorithm cipher, byte[] data, byte[] transformedKey)
    {
        Validate.notNull( cipher, "cipher must not be null" );
        Validate.notNull(data, "data must not be null");
        Validate.notNull( transformedKey, "transformedKey must not be null" );
        Validate.isTrue(data.length>0,"Master Key must have a length > 0 ");
        this.cipher = cipher;
        this.data = data;
        this.transformedKey = transformedKey;
    }

    private static SecretKey aesKey(byte[] key) {
        return new SecretKeySpec(key, "AES");
    }

    public byte[] decrypt(byte[] payload, byte[] encryptionIV) throws BadPaddingException
    {
        return process(payload, encryptionIV, false);
    }

    public byte[] encrypt(byte[] payload, byte[] encryptionIV) {
        try
        {
            return process(payload, encryptionIV, true);
        }
        catch (BadPaddingException e)
        {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    private byte[] process(byte[] payload, byte[] encryptionIV, boolean encrypt) throws BadPaddingException
    {
        /*
7) Depending on CIPHERID, set up a decryption context with key master_key and IV ENCRYPTIONIV.
For the default AES encryption, use AES-CBC with PKCS#7-style padding. This will yield raw_payload_area.
         */
        try
        {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(this.data, "AES");
            AlgorithmParameterSpec paramSpec = new IvParameterSpec(encryptionIV);
            cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKeySpec, paramSpec);
            return cipher.doFinal(payload);
        }
        catch(BadPaddingException e) {
            throw e;
        }
        catch(Exception e) {
            throw new RuntimeException("Decryption failed",e);
        }
    }
}