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
import de.codesourcery.keepass.core.datamodel.Entry;
import de.codesourcery.keepass.core.datamodel.EntryGroup;
import de.codesourcery.keepass.core.datamodel.KeyValueItem;
import de.codesourcery.keepass.core.datamodel.UUID;
import de.codesourcery.keepass.core.fileformat.Database;
import de.codesourcery.keepass.core.fileformat.XmlPayloadView;
import de.codesourcery.keepass.core.util.IResource;
import de.codesourcery.keepass.core.util.Logger;
import de.codesourcery.keepass.core.util.LoggerFactory;
import de.codesourcery.keepass.core.util.Serializer;
import junit.framework.TestCase;

import javax.crypto.BadPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Map;

public class KdbxV4Test extends TestCase
{
    private static final Logger LOGGER;

    private static final String PASSWORD = "test";
    private static final List<Credential> CREDENTIALS = List.of(Credential.password( PASSWORD.toCharArray() ));

    static {
        LoggerFactory.currentLevel = Logger.Level.INFO;
        LoggerFactory.setLogAppender( (lvl, clazz, msg, t) -> {
            if ( lvl.severity  >= Logger.Level.INFO.severity )
            {
                System.out.println( lvl + " - " + msg );
                if ( t != null )
                {
                    t.printStackTrace();
                }
            }
        });
        LOGGER = LoggerFactory.getLogger( KdbxV4Test.class );
    }

    public void testLoadFileWithAesKDF() throws IOException, BadPaddingException
    {
        final Database db = load( "/keepassxc_v4_aes.kdbx" );
        XmlPayloadView view = new XmlPayloadView( db );
        assertEquals(1, view.getEntryCount() );
        assertEquals( 1, view.getGroups().size() );

        final EntryGroup group0 = view.getGroups().get( 0 );
        final Map<UUID, Entry> entryByUUID = group0.entries;
        assertEquals( 1, entryByUUID.size() );
        final Entry entry = entryByUUID.values().stream().limit( 1 ).findFirst().get();

        System.out.println( "Got entry  : " + entry.uuid.toHex() );
        System.out.println( "Entry times: " + entry.times);

        // check entry values
        final Map<String, KeyValueItem<?>> items = entry.items;
        assertEquals( 6, items.size() );
        assertEquals("https://test2.de", items.get("KP2A_URL").value);
        assertEquals("", items.get("Notes").value);
        assertEquals("testpassword", items.get("Password").value);
        assertEquals("Test entry #1", items.get("Title").value);
        assertEquals("https://test.de", items.get("URL").value);
        assertEquals("test user", items.get("UserName").value);
    }

    public void testLoadFileWithArgon2dKDF() throws IOException, BadPaddingException
    {
        final Database db = load("/keepassxc_v4_argon2d.kdbx" );
        XmlPayloadView view = new XmlPayloadView( db );
        assertEquals(1, view.getEntryCount() );
        assertEquals( 1, view.getGroups().size() );

        final EntryGroup group0 = view.getGroups().get( 0 );
        final Map<UUID, Entry> entryByUUID = group0.entries;
        assertEquals( 1, entryByUUID.size() );
        final Entry entry = entryByUUID.values().stream().limit( 1 ).findFirst().get();

        System.out.println( "Got entry  : " + entry.uuid.toHex() );
        System.out.println( "Entry times: " + entry.times);

        // check entry values
        final Map<String, KeyValueItem<?>> items = entry.items;
        assertEquals( 6, items.size() );
        assertEquals("https://test2.de", items.get("KP2A_URL").value);
        assertEquals("", items.get("Notes").value);
        assertEquals("testpassword", items.get("Password").value);
        assertEquals("Test entry #1", items.get("Title").value);
        assertEquals("https://test.de", items.get("URL").value);
        assertEquals("test user", items.get("UserName").value);
    }

    public void testMergeV3AndV4_v4FileHasMoreRecentEntry() throws IOException, BadPaddingException
    {
        final Database older = load("/src1_kdbx3.kdbx" );
        // note: since converting from v4 file format to v3 file format is lossy,
        //       XmlPayloadView#merge() will currently always merge into the v4 file
        final Database expectedMergeTarget = load("/dst1_kdbx4.kdbx" );

        final MergeHelper.MergeResult result = MergeHelper.combine( List.of( older, expectedMergeTarget ), LOGGER );
        assertTrue( "Destination changed ?", result.mergedDatabaseChanged() );
        assertSame( expectedMergeTarget, result.mergedDatabase() );

        final Database readAgain = readWrite( result.mergedDatabase() );

        final XmlPayloadView view = new XmlPayloadView( readAgain );

        assertEquals( 1, view.getGroups().size() );
        final EntryGroup group = view.getGroup( "Root" ).get();
        assertEquals( 2, group.size() );

        assertEntryHasPassword( view, "entry1" , "password1_more_recent" );
        assertEntryHasPassword( view, "entry2" , "password2" );
    }

    public void testReadArgon2() throws IOException, BadPaddingException {
        final Database db = load("/keepassxc_v4_argon2d.kdbx");
        assertNotNull( db );
    }

    public void testMergeIdenticalFilesWithDifferentFileFormatVersionsDoesNothing() throws IOException, BadPaddingException {
        // kdbx3_identical.kdbx
        final Database db1 = load("/kdbx3_identical.kdbx" );
        final Database db2 = load("/kdbx4_identical.kdbx" );

        final MergeHelper.MergeResult result = MergeHelper.combine( List.of( db1, db2 ), LOGGER );
        assertFalse( result.mergedDatabaseChanged() );
    }

    // kdbx4_aes_with_kdb4_kdf.kdbx
    public void testReadWithKdbX4KDF() throws IOException, BadPaddingException {
        final Database db = load("/kdbx4_aes_with_kdb4_kdf.kdbx");
        assertNotNull( db );
    }

    public void testMergeV3AndV4_v3FileHasMoreRecentEntry() throws IOException, BadPaddingException
    {
        final Database older = load("/kdbx3_more_recent.kdbx" );
        debugPrint( older );
        // note: since converting from v4 file format to v3 file format is lossy,
        //       XmlPayloadView#merge() will currently always merge into the v4 file
        final Database expectedMergeTarget = load("/kdbx4_less_recent.kdbx" );
        debugPrint( expectedMergeTarget );

        final MergeHelper.MergeResult result = MergeHelper.combine( List.of( older, expectedMergeTarget ), LOGGER );
        assertTrue( "Destination changed ?", result.mergedDatabaseChanged() );
        assertSame( expectedMergeTarget, result.mergedDatabase() );

        final Database readAgain = readWrite( result.mergedDatabase() );
        final XmlPayloadView view = new XmlPayloadView( readAgain );

        assertEquals( 1, view.getGroups().size() );
        final EntryGroup group = view.getGroup( "Root" ).get();
        assertEquals( 2, group.size() );

        assertEntryHasPassword( view, "entry1" , "password1" );
        assertEntryHasPassword( view, "entry2" , "password2_more_recent" );
    }

    // ================== helper functions =================

    private static Database readWrite(Database db) throws IOException, BadPaddingException
    {
        System.out.println( "read-write -> " + db.resource );
        final ByteArrayOutputStream bout = new ByteArrayOutputStream();
        final Serializer outBuffer = new Serializer( bout );
        db.write( CREDENTIALS , outBuffer, null , LOGGER  );
        return Database.read( CREDENTIALS, IResource.inputStream( bout, "test data" ) );
    }

    private static void assertEntryHasPassword( XmlPayloadView view, String entryTitle, String expectedPassword) {
        final EntryGroup root = view.getGroup( "Root" ).get();
        final Entry entry = root.getEntryByTitle( entryTitle ).get();
        assertEquals( expectedPassword, entry.getPassword().get() );
    }

    private static void debugPrint(Database db) {
        final XmlPayloadView view = new XmlPayloadView( db);
        final EntryGroup grp = view.getGroup( "Root" ).get();
        grp.entries().forEach( entry -> {
            System.out.println( "Entry '" + entry.getTitle() + "' -> " + entry.item( "Password" ).get().value );
        });
    }

    private static Database load(String database) throws IOException, BadPaddingException
    {
        return Database.read( CREDENTIALS, IResource.classpath( database ) );
    }
}