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

import de.codesourcery.keepass.core.crypto.Credential;
import de.codesourcery.keepass.core.fileformat.Database;
import de.codesourcery.keepass.core.util.IResource;
import de.codesourcery.keepass.core.util.Logger;
import de.codesourcery.keepass.core.util.LoggerFactory;
import junit.framework.TestCase;

import javax.crypto.BadPaddingException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class MergeTest extends TestCase
{
    private Logger logger(List<String> messages) {
        return (level, msg, t) -> messages.add(msg);
    }

    public void testMergeMultipleTimes() throws IOException, BadPaddingException
    {
        LoggerFactory.currentLevel = Logger.Level.TRACE;

        final List<Credential> credentials = List.of(Credential.password("test".toCharArray()));
        final IResource resource1 = IResource.classpath("/mergetest_1.kdbx");
        final IResource resource2 = IResource.classpath("/mergetest_2.kdbx");
        final Database db1 = new Database().load(credentials,resource1);
        final Database db2 = new Database().load(credentials,resource2);

        System.out.println("============= merge #1 ============");
        final List<String> messages = new ArrayList<>();

        boolean dbChanged = MergeHelper.combine(List.of(db1,db2),logger(messages)).isPresent();
        assertTrue(dbChanged);

        assertTrue( messages.stream().anyMatch(x -> x.contains( "Replacing entry ZabZxYVp54uFOVCvdosurw== ('Entry #1 (updated once)') from 2020-06-02T11:22:33Z with entry Entry #1 (updated twice) , modified on 2020-06-02T11:22:47Z" )));
        assertTrue( messages.stream().anyMatch(x -> x.contains( "Replacing entry hFasaI7w+soFfXCtHn2VvQ== ('Entry #2') from 2020-06-02T10:43:09Z with entry Entry #2 , modified on 2020-06-02T10:43:57Z" )));

        System.out.println("============= merge #2 ============");
        messages.clear();
        dbChanged = MergeHelper.combine(List.of(db1,db2),logger(messages)).isPresent();
        assertFalse(dbChanged);
        assertTrue(messages.stream().anyMatch(x -> x.contains("Combining the files yielded no changes")));
    }

    public void testMergeEntriesByTitle() throws IOException, BadPaddingException
    {
        final List<Credential> credentials = List.of(Credential.password("test".toCharArray()));
        final IResource resource1 = IResource.classpath("/merge_by_title1.kdbx");
        final IResource resource2 = IResource.classpath("/merge_by_title2.kdbx");
        final Database db1 = new Database().load(credentials,resource1);
        final Database db2 = new Database().load(credentials,resource2);

        System.out.println("============= merge #1 ============");
        final List<String> messages = new ArrayList<>();

        boolean dbChanged = MergeHelper.combine(List.of(db1,db2),logger(messages)).isPresent();
        assertTrue(dbChanged);

        assertTrue(messages.stream().anyMatch(x -> x.contains("Locating entry with UUID 6pERdkjul0TJ9SJ0JNl3KQ== failed but using title 'Entry #1' succeeded.")));
        assertTrue( messages.stream().anyMatch(x -> x.contains( "Replacing entry O3t2bZc6QuT8SQ+GhqOHpw== ('Entry #1') from 2020-06-03T13:40:36Z with entry Entry #1 , modified on 2020-06-03T13:47:14Z")));
        assertTrue(messages.stream().anyMatch(x -> x.contains("Destination file has been updated")));

        System.out.println("============= merge #2 ============");
        messages.clear();
        dbChanged = MergeHelper.combine(List.of(db1,db2),logger(messages)).isPresent();
        assertFalse(dbChanged);
        assertTrue(messages.stream().anyMatch(x -> x.contains("Combining the files yielded no changes")));
    }
}
