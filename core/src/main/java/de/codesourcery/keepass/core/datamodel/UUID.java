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
package de.codesourcery.keepass.core.datamodel;

import de.codesourcery.keepass.core.util.Misc;
import org.apache.commons.lang3.Validate;

import java.util.Arrays;
import java.util.Base64;

/**
 * A KeePassX UUID used to uniquely identify objects inside the payload XML.
 *
 *  @author tobias.gierke@code-sourcery.de
 */
public class UUID
{
    private final byte[] data;

    public UUID(byte[] data)
    {
        Validate.notNull(data, "data must not be null");
        Validate.isTrue(data.length > 0, "UUID must have at least length 1 but had "+data.length);
        this.data = data;
    }

    public static UUID fromHex(String hex) {
        return new UUID( Misc.fromHexString( hex ) );
    }

    public String base64() {
        return Base64.getEncoder().encodeToString(this.data);
    }

    @Override
    public boolean equals(Object o)
    {
        if (o instanceof UUID x)
        {
            return Arrays.equals(x.data,this.data);
        }
        return false;
    }

    @Override
    public int hashCode()
    {
        return Arrays.hashCode(data);
    }

    @Override
    public String toString()
    {
        return base64();
    }

    public String toHex() {
        return Misc.toHexString( this.data, "" );
    }
}
