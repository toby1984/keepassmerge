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

import de.codesourcery.keepass.core.fileformat.Database;
import org.apache.commons.lang3.Validate;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Stream;

/**
 * A group of password entries.
 * @author tobias.gierke@code-sourcery.de
 */
public class EntryGroup
{
    public final String name;
    public final UUID uuid;
    public Database database;

    // MUST be a LinkedHashMap as we need to preserve the order
    // identical to what we've found in the XML so that
    // decoding passwords protected with SALSA20 (or some other stream cipher)
    // works correctly. The cipher is only initialized once and then the
    // outcome of each operation always depends on all previous operations,
    // so messing with the encryption order would render the result unusable.
    public final Map<UUID,Entry> entries = new LinkedHashMap<>();
    public Times times;

    public EntryGroup(String name, UUID uuid)
    {
        this.name = name;
        this.uuid = uuid;
    }

    public void add(Entry e) {
        Validate.notNull(e, "e must not be null");
        if ( entries.containsKey(e.uuid) ) {
            throw new IllegalArgumentException("Duplicate entry "+e.uuid);
        }
        if ( e.group != null && e.group != this ) {
            throw new IllegalArgumentException("Entry is already associated with a different group");
        }
        e.group = this;
        entries.put(e.uuid,e);
    }

    public Stream<Entry> entries() {
        return entries.values().stream();
    }

    public Optional<Entry> getEntryByUUID(UUID uuid) {
        return entries().filter( x -> x.uuid.equals(uuid) ).findFirst();
    }

    public Optional<Entry> getEntryByTitle(String title) {
        final Predicate<Entry> pred = e -> e.item("Title").filter(x -> x.hasValue(title) ).isPresent();
        return entries().filter(pred).findFirst();
    }

    @Override
    public String toString()
    {
        return "EntryGroup{" +
                   "name='" + name + '\'' +
                   ", uuid=" + uuid +
                   ", database=" + database +
                   '}';
    }
}
