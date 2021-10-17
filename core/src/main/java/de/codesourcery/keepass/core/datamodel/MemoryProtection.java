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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Configuration that tracks which key/value items inside the XML payload
 * need to be encrypted/decrypted using the {@link Database#getInnerEncryptionAlgorithm inner encryption algorithm}.
 *
 * @author tobias.gierke@code-sourcery.de
 * @see Database#getInnerEncryptionAlgorithm()
 */
public class MemoryProtection
{
    /**
     * Enumeration of 'items' inside the XML that may be encrypted.
     */
    public enum ProtectedItem
    {
        TITLE,
        USERNAME,
        PASSWORD,
        URL,
        NOTES;

        public static Optional<ProtectedItem> lookupByKeyName(String keyName) {
            Validate.notBlank( keyName, "keyName must not be null or blank");
            ProtectedItem item = switch( keyName ) {
                case "Title" -> ProtectedItem.TITLE;
                case "UserName" -> ProtectedItem.USERNAME;
                case "Password" -> ProtectedItem.PASSWORD;
                case "URL" -> ProtectedItem.URL;
                case "Notes" -> ProtectedItem.NOTES;
                // At least KeePassXC stores additional URLs using these keys
                default -> keyName.matches( "^KP2A_URL(_\\d+)?$" ) ? ProtectedItem.URL : null;
            };
            return Optional.ofNullable( item );
        }
    }

    private final Map<ProtectedItem,Boolean> settings;

    public MemoryProtection() {
        settings = new HashMap<>();
        Arrays.stream( ProtectedItem.values() ).forEach(x -> settings.put(x,Boolean.TRUE));
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