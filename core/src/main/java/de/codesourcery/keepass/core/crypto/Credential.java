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

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

/**
 * User provided credential.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class Credential
{
    enum Type {
        PASSWORD,
        KEYFILE_KEY,
        WINDOWS_USER_ACCOUNT;
    }

    public final Type type;
    public final byte[] data;

    private Credential(Type type, byte[] data)
    {
        Validate.notNull(type, "type must not be null");
        Validate.notNull(data, "data must not be null");
        Validate.isTrue(data.length>0, "Data length must be > 0");
        this.type = type;
        this.data = data;
    }

    @Override
    public String toString()
    {
        return "Credential{" +
                   "type=" + type +
                   ", data=" + Arrays.toString(data) +
                   '}';
    }

    public static Credential password(char[] pwd) {
        try
        {
            final byte[] bytes = new String(pwd).getBytes("UTF8");
            return new Credential(Type.PASSWORD,bytes);
        }
        catch (UnsupportedEncodingException e)
        {
            throw new RuntimeException(e);
        }
    }
}
