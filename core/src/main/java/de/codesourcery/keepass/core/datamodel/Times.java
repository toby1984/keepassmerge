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

import java.time.ZonedDateTime;

/**
 * Entity that contains time-related information for XML payload password entries and groups.
 * @author tobias.gierke@code-sourcery.de
 */
public class Times
{
    public ZonedDateTime lastModificationTime;
    public ZonedDateTime creationTime;
    public ZonedDateTime lastAccessTime;
    public ZonedDateTime expiryTime;
    public boolean expires;
    public int usageCount;
    public ZonedDateTime locationChanged;
}
