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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Derived KeePassX 'master key' that is used to encrypt/decrypt the actual payload.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class MasterKey
{
    private static final Logger LOG = LoggerFactory.getLogger( MasterKey.class );

    public final byte[] data;

    public MasterKey(byte[] data)
    {
        Validate.notNull(data, "data must not be null");
        Validate.isTrue(data.length>0,"Master Key must have a length > 0 ");
        this.data = data;
    }

    public static MasterKey create(CompositeKey compKey,
                                   TypeLengthValue transformSeed,
                                   TypeLengthValue masterSeed,
                                   long encryptionRounds,
                                   boolean isBenchmark)
    {
        Validate.notNull(compKey, "compKey must not be null");
        Validate.notNull(transformSeed, "transformSeed must not be null");
        Validate.notNull(masterSeed, "masterSeed must not be null");
        Validate.isTrue( encryptionRounds > 0, "Expected encryption rounds to be > 1");

        Validate.isTrue( transformSeed.hasType(TypeLengthValue.Type.TRANSFORM_SEED), "Expected a transform seed");
        Validate.isTrue( masterSeed.hasType(TypeLengthValue.Type.MASTER_SEED ), "Expected a master seed" );

        /*
         * Generate the final master key from the composite key
         *
         * This part is the same for .kdb and .kdbx files. In both file format, you should have get from the header :
         *
         *     a Transform Seed,
         *     a number N of Encryption Rounds ,
         *     a Master Seed.
         *
         * To generate the final master key, you first need to generate the transformed key :
         */
        // 1. create an AES cipher, taking Transform Seed as its key/seed,
        final SecretKey aes = aesKey(transformSeed.rawValue);
    // 2. initialize the transformed key value with the composite key value (transformed_key = composite_key),
        byte[] transformKey = new byte[ compKey.data.length ];
        System.arraycopy(compKey.data,0,transformKey,0,compKey.data.length);
    // 3. use this cipher to encrypt the transformed_key N times ( transformed_key = AES(transformed_key), N times),

        final long now = System.currentTimeMillis();
        if ( ! isBenchmark )
        {
            LOG.info("Running " + encryptionRounds + " encryption rounds...");
        }

        final Cipher cipher;
        try
        {
            cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, aes);
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }

        for ( long i = 0 ; i < encryptionRounds ; i++ )
        {
            if ( (i%10000) == 0 )
            {
                if ( ! isBenchmark )
                {
                    LOG.trace("Done ... " + i + " out of " + encryptionRounds + ", text length: " + transformKey.length);
                }
            }
            try
            {
                final int initialSize=transformKey.length;
                transformKey = cipher.doFinal(transformKey);
                if ( transformKey.length != initialSize ) {
                    throw new RuntimeException("Key grew by " + (transformKey.length-initialSize) + " bytes");
                }
            }
            catch (Exception e)
            {
                throw new RuntimeException(e);
            }
        }

        final long elapsedMillis = System.currentTimeMillis() - now;
        if ( ! isBenchmark )
        {
            LOG.info("Running " + encryptionRounds + " encryption rounds took " + elapsedMillis + " ms");
        }

    // 4. hash (with SHA-256) the transformed_key (transformed_key = sha256(transformed_key) ),
        transformKey = Hash.sha256(transformKey);

    // 5. concatenate the Master Seed to the transformed_key (transformed_key = concat(Master Seed, transformed_key) ),
        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.writeBytes( masterSeed.rawValue);
        bos.writeBytes( transformKey );

    // 6. hash (with SHA-256) the transformed_key to get the final master key (final_master_key = sha256(transformed_key) ).
        final byte[] masterKey = Hash.sha256(bos.toByteArray());

        // You now have the final master key, you can finally decrypt the database
        // (the part of the file after the header for .kdb, and after the End of Header field for .kdbx).
        return new MasterKey(masterKey);
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