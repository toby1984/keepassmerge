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
package de.codesourcery.keepass.core;

import de.codesourcery.keepass.core.fileformat.Database;
import de.codesourcery.keepass.core.fileformat.XmlPayloadView;
import de.codesourcery.keepass.core.util.Logger;
import de.codesourcery.keepass.core.util.LoggerFactory;
import org.apache.commons.lang3.Validate;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * Helper class to combine the data from multiple {@link Database files}.
 *
 *  @author tobias.gierke@code-sourcery.de
 */
public class MergeHelper
{
    private static final Logger LOG = LoggerFactory.getLogger(MergeHelper.class);

    /**
     * Perform merge.
     *
     * @param sources databases to combine
     * @param progressCallback callback invoked to provide progress information to the user
     * @return combined database file.
     */
    public static Optional<Database> combine(Collection<Database> sources, Logger progressCallback)
    {
        Validate.notNull(sources, "sources must not be null");

        final List<XmlPayloadView> views = sources.stream()
                                               .map(XmlPayloadView::new)
                                               .collect(Collectors.toList());

        if ( views.size() < 2 ) {
            throw new IllegalArgumentException("Need at least 2 databases to merge");
        }

        // use database which has the most entries
        // as merge target
        XmlPayloadView mostEntriesView = null;
        int mostEntries=0;
        for ( XmlPayloadView view : views )
        {
            final int cnt = view.getEntryCount();
            progressCallback.info("File " + view.database.resource + " contains " + cnt + " entries.");
            LOG.info("File " + view.database.resource + " contains " + cnt + " entries.");
            if ( mostEntriesView == null || cnt > mostEntries ) {
                mostEntriesView = view;
                mostEntries = cnt;
            }
        }
        progressCallback.info("Going to merge into file " + mostEntriesView.database.resource + " with " + mostEntries + " entries.");
        LOG.info("Going to merge into file " + mostEntriesView.database.resource + " with " + mostEntries + " entries.");
        views.remove(mostEntriesView);
        final XmlPayloadView finalMostEntriesView=mostEntriesView;
        boolean dataChanged = false;
        for (XmlPayloadView v : views)
        {
            dataChanged |= finalMostEntriesView.merge(v, progressCallback);
        }
        if ( dataChanged ) {
            progressCallback.info("Destination file has been updated");
        } else {
            progressCallback.info("Combining the files yielded no changes");
        }
        return dataChanged ? Optional.of(mostEntriesView.database) : Optional.empty();
    }
}