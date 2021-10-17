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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Hashing algorithm used throughout the KeePassX encryption key derivation process.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class Hash
{
    private interface MD {
        void reset();
        MD update(byte[] input);

        default byte[] finish(byte[] input) {
            return finish( input, 0, input.length );
        }

        byte[] finish(byte[] input, int offset, int length);
    }

    private final String algorithm;
    private final Hash.MD digest;

    private static Hash.MD jdkMessageDigest(String algorithm)
    {
        try
        {
            final MessageDigest digest = MessageDigest.getInstance( algorithm );
            return new Hash.MD() {
                @Override
                public void reset()
                {
                    digest.reset();
                }

                @Override
                public Hash.MD update(byte[] input)
                {
                    digest.update( input );
                    return this;
                }

                @Override
                public byte[] finish(byte[] input, int offset, int length)
                {
                        digest.update( input, offset, length );
                        return digest.digest();
                }
            };
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new RuntimeException("No "+algorithm+" digest?");
        }
    }

    private Hash(String algorithm)
    {
        this( algorithm, jdkMessageDigest( algorithm ) );
    }

    private Hash(String algorithm, Hash.MD digest)
    {
        Validate.notBlank( algorithm, "algorithm must not be null or blank");
        this.algorithm = algorithm;
        this.digest = digest;
    }

    public void reset() {
        digest.reset();
    }

    public Hash update(byte[] input) {
        digest.update( input );
        return this;
    }

    public byte[] finish(byte[] input,int offset, int length) {
        return digest.finish( input, offset, length);
    }


    public byte[] finish(byte[] input) {
        return digest.finish( input );
    }

    public final byte[] digest(byte[] input) {
        reset();
        return finish( input );
    }

    public static Hash hmac256(byte[] key)
    {
        final Mac sha256_HMAC;
        try
        {
            sha256_HMAC = Mac.getInstance( "HmacSHA256" );
            sha256_HMAC.init( new SecretKeySpec( key, "HmacSHA256" ) );
        } catch( Exception e) {
            throw new RuntimeException( e );
        }
        Hash.MD md = new Hash.MD() {

            @Override
            public void reset()
            {
                sha256_HMAC.reset();
            }

            @Override
            public MD update(byte[] input)
            {
                sha256_HMAC.update( input );
                return this;
            }

            @Override
            public byte[] finish(byte[] input, int offset, int length)
            {
                sha256_HMAC.update( input, offset, length );
                return sha256_HMAC.doFinal();
            }
        };
        return new Hash("HMAC-256" , md );
    }

    public static Hash sha256() {
        return new Hash("SHA-256");
    }

    public static Hash sha512() {
        return new Hash("SHA-512");
    }

    public static byte[] sha256(byte[] data) {
        return sha256().digest(data);
    }
}