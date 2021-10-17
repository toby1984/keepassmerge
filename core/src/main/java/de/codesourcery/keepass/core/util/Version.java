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
package de.codesourcery.keepass.core.util;

public record Version(int major, int minor) implements Comparable<Version>
{
    @Override
    public String toString()
    {
        return major+"."+minor;
    }

    public boolean hasMajorVersion(int version) {
        return this.major == version;
    }

    @Override
    public int compareTo(Version o)
    {
        final int result = Integer.compare( this.major, o.major );
        return result != 0 ? result : Integer.compare( this.minor, o.minor );
    }
}
