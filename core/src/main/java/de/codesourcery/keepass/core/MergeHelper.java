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
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Helper class to combine the data from multiple {@link Database files}.
 *
 *  @author tobias.gierke@code-sourcery.de
 */
public class MergeHelper
{
    private static final Logger LOG = LoggerFactory.getLogger(MergeHelper.class);

    public static record MergeResult(Database mergedDatabase, boolean mergedDatabaseChanged) {}

    /**
     * Perform merge.
     *
     * Note that this method will pick the input database with the most entries
     * and use this one to merge all the others into. The result of this method
     * will indicate which database has been chosen as the merge destination.
     *
     * @param sources databases to combine
     * @param progressCallback callback invoked to provide progress information to the user
     * @return Merge result.
     */
    public static MergeResult combine(Collection<Database> sources, Logger progressCallback)
    {
        Validate.notNull(sources, "sources must not be null");
        Validate.isTrue( sources.size() >= 2, "Need at least 2 databases to merge");

        final List<XmlPayloadView> views = sources.stream().map(XmlPayloadView::new).collect(Collectors.toList());
        views.forEach( view ->
        {
            progressCallback.info( "combine(): " + view.database.resource + " (" + view.database.getAppVersion() + ")" );

            if ( Constants.DEBUG_MERGING ) {
                System.out.println( "------------------------- " + view.database.resource + " (" + view.database.getAppVersion() + ") -----------------------" );
                view.getGroups().stream().sorted((a,b)->a.name.compareToIgnoreCase( b.name ) ).forEach( group ->
                {
                    System.out.println( "\t+ Group: " + group.name );
                    group.entries().sorted((a,b) -> a.getTitle().compareToIgnoreCase( b.getTitle() )).forEach( entry ->
                    {
                        System.out.println( "\t\t+ Entry: '" + entry.getTitle()+"' ("+entry.times.lastModificationTime+") - "+entry.uuid.toHex());
                    });
                } );
            }
        } );

        // use database which has the most entries as merge target
        final Set<Integer> versions = views.stream().map( x->x.database.outerHeader.appVersion.major() ).collect( Collectors.toSet());

        // find the most recent file format major version and
        // consider only those files as merge targets that have the same major version
        // This is to avoid creating an incompatible file by accidentally things from
        // different file format major versions (assumes the file format uses semantic versioning though)
        final boolean differentAppVersions = versions.size() > 1;
        final List<XmlPayloadView> candidates;
        if ( differentAppVersions ) {
            final int largestMajorVersion = versions.stream().max( Integer::compareTo ).get();
            candidates = views.stream()
                .filter( x -> x.database.outerHeader.appVersion.major() == largestMajorVersion )
                .collect( Collectors.toList());
        } else {
            candidates = views;
        }
        XmlPayloadView mergeTarget = null;
        int mostEntries=0;
        for ( XmlPayloadView view : candidates )
        {
            final int cnt = view.getEntryCount();
            progressCallback.info("File " + view.database.resource + " contains " + cnt + " entries.");
            LOG.info("File " + view.database.resource + " contains " + cnt + " entries.");
            if ( mergeTarget == null || cnt > mostEntries ) {
                mergeTarget = view;
                mostEntries = cnt;
            }
        }
        final String msg = "Going to merge into file " + mergeTarget.database.resource + " (" + mergeTarget.database.getAppVersion() +
            ") with " + mostEntries + " entries.";
        if ( Constants.DEBUG_MERGING ) {
            System.out.println( msg );
        }
        progressCallback.info( msg );
        LOG.info(msg );

        views.remove(mergeTarget);

        boolean dataChanged = false;
        for (XmlPayloadView v : views)
        {
            dataChanged |= mergeTarget.merge(v, progressCallback);
        }
        if ( dataChanged ) {
            progressCallback.info("Destination file has been updated");
        } else {
            progressCallback.info("Combining the files yielded no changes");
        }
        return new MergeResult(mergeTarget.database,dataChanged);
    }
}