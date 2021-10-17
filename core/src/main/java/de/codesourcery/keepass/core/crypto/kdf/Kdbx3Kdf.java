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

import de.codesourcery.keepass.core.crypto.Hash;
import de.codesourcery.keepass.core.fileformat.VariantDictionary;
import de.codesourcery.keepass.core.util.Logger;
import de.codesourcery.keepass.core.util.Misc;
import org.apache.commons.lang3.Validate;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class Kdbx3Kdf implements KeyDerivationFunction
{
    private static final Logger LOG = de.codesourcery.keepass.core.util.LoggerFactory.getLogger( Kdbx3Kdf.class );

    private long rounds;
    private byte[] seed;
    private boolean isBenchmark;
    private VariantDictionary additionalParams;

    @Override
    public void init(long rounds, byte[] seed, boolean isBenchmark, VariantDictionary params)
    {
        this.rounds = rounds;
        this.seed = seed;
        this.isBenchmark = isBenchmark;
        this.additionalParams = params;
    }

    //     virtual bool transform(const QByteArray& raw, QByteArray& result) const = 0;
    @Override
    public byte[] transform(byte[] raw)
    {
        Validate.isTrue( raw != null && raw.length == 32 );

        /*
    QByteArray resultLeft;
    QByteArray resultRight;

    QFuture<bool> future = QtConcurrent::run(transformKeyRaw, raw.left(16), m_seed, m_rounds, &resultLeft);

    bool rightResult = transformKeyRaw(raw.right(16), m_seed, m_rounds, &resultRight);
    bool leftResult = future.result();

    if (!rightResult || !leftResult) {
        return false;
    }
         */
        final byte[] resultLeft = transformKeyRaw(
            Arrays.copyOfRange( raw, 0,16 ),
            seed,
            rounds);
        final byte[] resultRight = transformKeyRaw(
            Arrays.copyOfRange( raw, 16,32 ),
            seed,
            rounds);

/*
    QByteArray transformed;
    transformed.append(resultLeft);
    transformed.append(resultRight);

    result = CryptoHash::hash(transformed, CryptoHash::Sha256);
    return true;
 */
        final byte[] transformed = Misc.concat( resultLeft, resultRight );
         return Hash.sha256( transformed );
    }

    /*
bool AesKdf::transformKeyRaw(const QByteArray& key, const QByteArray& seed, int rounds, QByteArray* result)
{
    *result = key;
    return SymmetricCipher::aesKdf(seed, rounds, *result);
}
     */
    private byte[] transformKeyRaw(byte[] key, byte[] seed, long rounds) {
        return aesKdf( seed, rounds, key );
    }

    /*
bool SymmetricCipher::aesKdf(const QByteArray& key, int rounds, QByteArray& data)
{
    try {
        std::unique_ptr<Botan::BlockCipher> cipher(Botan::BlockCipher::create("AES-256"));
        cipher->set_key(reinterpret_cast<const uint8_t*>(key.data()), key.size());

        Botan::secure_vector<uint8_t> out(data.begin(), data.end());
        for (int i = 0; i < rounds; ++i) {
            cipher->encrypt(out);
        }
        std::copy(out.begin(), out.end(), data.begin());
        return true;
    } catch (std::exception& e) {
        qWarning("SymmetricCipher::aesKdf: Could not process: %s", e.what());
        return false;
    }
}
     */
    private byte[] aesKdf(byte[] key, long rounds,byte[] initialData) {

        byte[] result = new byte[initialData.length];
        System.arraycopy( initialData, 0, result, 0, result.length );

        try
        {
            final Cipher cipher = Cipher.getInstance( "AES/ECB/NoPadding" );
            cipher.init( Cipher.ENCRYPT_MODE, aesKey( key ) );
            for ( long i = 0; i < rounds; i++ )
            {
                result = cipher.doFinal( result );
            }
        }
        catch( Exception e )
        {
            throw new RuntimeException( e );
        }
        return result;
    }

    private static SecretKey aesKey(byte[] key) {
        return new SecretKeySpec(key, "AES");
    }
}
