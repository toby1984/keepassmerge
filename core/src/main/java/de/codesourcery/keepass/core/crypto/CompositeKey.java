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

import java.io.ByteArrayOutputStream;
import java.util.List;
import java.util.Optional;

/**
 * KeePassX 'composite key' created out of hashing & concatenating the user-provided credentials.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class CompositeKey
{
    public final byte[] data;

    private CompositeKey(byte[] data)
    {
        Validate.notNull(data, "data must not be null");
        Validate.isTrue(data.length > 0, "data length must be > 0");
        this.data = data;
    }

    public static CompositeKey create(List<Credential> credentials) {

        final Optional<Credential> password = credentials.stream().filter(x->x.type == Credential.Type.PASSWORD).findFirst();
        final Optional<Credential> keyfile = credentials.stream().filter(x->x.type == Credential.Type.KEYFILE_KEY).findFirst();
        final Optional<Credential> windowsUserAccount = credentials.stream().filter(x->x.type == Credential.Type.WINDOWS_USER_ACCOUNT).findFirst();

        final Hash digest = Hash.sha256();

        // To generate the composite key for a .kdbx file :
        //     1. You must hash (with SHA-256) all credentials needed (passphrase, key of the keyfile, Windows User Account),
        final Optional<byte[]> passwordHash = password.map(x -> digest.digest(x.data));
        final Optional<byte[]> keyfileHash = keyfile.map(x -> digest.digest(x.data));
        final Optional<byte[]> windowUserAccountHash = windowsUserAccount.map(x -> digest.digest(x.data));

        //     2. You must then concatenate ALL hashed credentials in this order : passphrase, keyfile, Windows User Account,
        final ByteArrayOutputStream concat = new ByteArrayOutputStream();
        passwordHash.ifPresent(concat::writeBytes );
        keyfileHash.ifPresent(concat::writeBytes );
        windowUserAccountHash.ifPresent(concat::writeBytes );

        // 3. You must then hash the result of the concatenation.
        // Even though you have just one credential (for example, just a passphrase),
        // you still need to hash it twice (a first one for the step 1, and second one for the step 3).
        // The result of the hash is the composite key
        return new CompositeKey(digest.digest(concat.toByteArray() ));
    }
}
