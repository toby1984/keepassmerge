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

import org.apache.commons.lang3.Validate;

import java.util.Objects;

/**
 * Type-safe XML payload key/value item.
 *
 * @param <T>
 * @author tobias.gierke@code-sourcery.de
 */
public abstract class KeyValueItem<T>
{
    public final String key;
    public T value;
    public boolean valueProtected;
    public Entry owningEntry;

    public boolean hasValue(Object value) {
        return Objects.equals(this.value, value );
    }

    public KeyValueItem(Entry owningEntry, String key, T value)
    {
        Validate.notNull(owningEntry, "owningEntry must not be null");
        Validate.notBlank( key, "key must not be null or blank");
        this.owningEntry = owningEntry;
        this.key = key;
        this.value = value;
    }

    public abstract KeyValueItem<T> createCopy(Entry owningEntry);

    @Override
    public final boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (o == null || getClass() != o.getClass())
        {
            return false;
        }
        KeyValueItem<?> that = (KeyValueItem<?>) o;
        return key.equals(that.key) &&
                   Objects.equals(value, that.value);
    }

    @Override
    public final int hashCode()
    {
        return Objects.hash(key, value);
    }

    @Override
    public String toString()
    {
        return "KeyValueItem{" +
                   "key='" + key + '\'' +
                   ", value=" + value +
                   ", valueProtected=" + valueProtected +
                   '}';
    }
}