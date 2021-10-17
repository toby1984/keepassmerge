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

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

public class CipherStreamFactory
{
    public static InputStream decryptInputStream(OuterEncryptionAlgorithm cipherId, MasterKey master, byte[] iv, InputStream toWrap)
    {
        return new javax.crypto.CipherInputStream( toWrap, createDecryptionCipher( cipherId, master, iv ) );
    }

    public static OutputStream encryptOutputStream(OuterEncryptionAlgorithm cipherId, MasterKey master, byte[] iv, OutputStream toWrap)
    {
        return new javax.crypto.CipherOutputStream( toWrap, createEncryptionCipher( cipherId, master, iv ) );
    }

    private static Cipher createEncryptionCipher(OuterEncryptionAlgorithm cipherId, MasterKey master, byte[] iv) {
        return createCipher( cipherId, master, iv, true );
    }

    private static Cipher createDecryptionCipher(OuterEncryptionAlgorithm cipherId, MasterKey master, byte[] iv) {
        return createCipher( cipherId, master, iv, false);
    }

    private static Cipher createCipher(OuterEncryptionAlgorithm cipherId, MasterKey master, byte[] iv, boolean encrypt)
    {
        try
        {
            final Cipher cipher;
            final SecretKeySpec secretKeySpec;
            final AlgorithmParameterSpec paramSpec;
            switch( cipherId ) {
                case AES_128, AES_256 -> {
                    cipher = Cipher.getInstance( "AES/CBC/PKCS5Padding" );
                    secretKeySpec = new SecretKeySpec( master.data, "AES" );
                    paramSpec = new IvParameterSpec( iv );
                }
                default -> throw new IllegalArgumentException( "Sorry, cipher " + cipherId + " is not implemented yet" );
            }
            cipher.init( encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKeySpec, paramSpec );
            return cipher;
        }
        catch( NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchPaddingException e )
        {
            throw new RuntimeException( e );
        }
    }
}