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

import de.codesourcery.keepass.core.fileformat.FileHeader;
import org.apache.commons.lang3.Validate;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Information which key/value items inside the XML payload
 * are encrypted using the {@link FileHeader#getInnerEncryptionAlgorithm() 'inner encryption algorithm'}.
 *
 * @author tobias.gierke@code-sourcery.de
 * @see FileHeader#getInnerEncryptionAlgorithm()
 */
public class MemoryProtection
{
    private static final Map<String,ProtectedItem> KEY_TO_ITEM;

    public enum ProtectedItem
    {
        TITLE("Title"),
        USERNAME("UserName"),
        PASSWORD("Password"),
        URL("URL"),
        NOTES("Notes");
        public final String xmlKeyValue;

        ProtectedItem(String xmlKeyValue)
        {
            this.xmlKeyValue = xmlKeyValue;
        }

        public static ProtectedItem lookupByKeyName(String keyName) {
            Validate.notBlank( keyName, "keyName must not be null or blank");
            final ProtectedItem item = KEY_TO_ITEM.get(keyName);
            if ( item == null ) {
                throw new IllegalArgumentException("Unknown key '"+keyName+"'");
            }
            return item;
        }
    }

    static {
        KEY_TO_ITEM = Collections.unmodifiableMap(Arrays.stream(ProtectedItem.values()).collect(Collectors.toMap(x->x.xmlKeyValue,y->y)));
    }

    private final Map<ProtectedItem,Boolean> settings;

    public MemoryProtection() {
        settings = new HashMap<>();
        Arrays.stream( ProtectedItem.values() ).forEach(x -> settings.put(x,Boolean.TRUE));
    }

    public boolean hasAnyProtectedItems() {
        return Arrays.stream( ProtectedItem.values() ).anyMatch(settings::get);
    }

    public boolean isProtectionEnabled(ProtectedItem item) {
        Validate.notNull(item, "item must not be null");
        return settings.get(item);
    }

    public void setProtectionEnabled(ProtectedItem item, boolean onOff) {
        Validate.notNull(item, "item must not be null");
        settings.put( item, onOff );
    }
}