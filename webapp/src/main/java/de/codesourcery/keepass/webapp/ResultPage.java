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
package de.codesourcery.keepass.webapp;

import java.io.Serializable;
import java.util.List;

/**
 * Helper class for pagination on the UI that wraps the data to display as well
 * as the offset and limit values used when fetching the data.
 *
 * @param <T> type of elements in this page
 */
public record ResultPage<T>(int offset, List<T>results, int totalCount) implements Serializable
{
}
