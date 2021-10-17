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

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * A password entry.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class Entry
{
    public EntryGroup group;
    public UUID uuid;
    public Times times;

    // MUST be a LinkedHashMap as we need to preserve the order
    // identical to what we've found in the XML so that
    // decoding passwords protected with SALSA20 (or some other stream cipher)
    // works correctly. The cipher is only initialized once and then the
    // outcome of each operation always depends on all previous operations,
    // so messing with the encryption order would render the result unusable.
    public final Map<String, KeyValueItem<?>> items=new LinkedHashMap<>();

    public Entry(UUID uuid) {
        Validate.notNull(uuid, "uuid must not be null");
        this.uuid = uuid;
    }

    public Optional<String> getPassword() {
        return item( "Password" ).map( x -> (String) x.value );
    }

    public UUID getUuid()
    {
        return uuid;
    }

    public Optional<KeyValueItem<?>> item(String key) {
        return Optional.ofNullable(items.get(key) );
    }

    public String getTitle() {
        return (String) items.get("Title").value;
    }

    public void add(KeyValueItem<?> item) {
        if ( items.containsKey(item.key) ) {
            throw new IllegalArgumentException("Duplicate item key "+item.key);
        }
        if ( item.owningEntry != null && item.owningEntry != this ) {
            throw new IllegalStateException("Item is already owned by "+item.owningEntry);
        }
        item.owningEntry = this;
        items.put(item.key, item);
    }

    public void setUuid(UUID uuid)
    {
        Validate.notNull(uuid, "uuid must not be null");
        this.uuid = uuid;
    }

    @Override
    public String toString()
    {
        return "Entry{uuid="+uuid+",title="+getTitle()+",group="+group+"}";
    }
}