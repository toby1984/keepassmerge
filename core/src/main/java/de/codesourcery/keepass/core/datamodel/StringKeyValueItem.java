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

/**
 * A string key/value item.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class StringKeyValueItem extends KeyValueItem<String>
{
    public StringKeyValueItem(Entry owningEntry, String key, String value)
    {
        super(owningEntry, key, value);
    }

    @Override
    public StringKeyValueItem createCopy(Entry owningEntry)
    {
        final StringKeyValueItem result = new StringKeyValueItem(owningEntry, this.key, this.value);
        result.valueProtected = valueProtected;
        return result;
    }
}
