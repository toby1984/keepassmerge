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
import de.codesourcery.keepass.core.datamodel.StringKeyValueItem;
import de.codesourcery.keepass.core.fileformat.Database;
import de.codesourcery.keepass.core.fileformat.XmlPayloadView;
import de.codesourcery.keepass.core.util.IResource;
import de.codesourcery.keepass.core.util.Serializer;
import de.codesourcery.keepass.core.util.XmlHelper;
import junit.framework.TestCase;

import javax.crypto.BadPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;

public class MainTest extends TestCase
{
    public void testV31Roundtrip() throws IOException, BadPaddingException
    {
        final List<Credential> credentials = List.of(Credential.password("test".toCharArray()));
        final IResource resource = IResource.classpath("/test.kdbx");

        final Database db = Database.read( credentials, resource );

        System.out.println("OK");
        System.out.println(XmlHelper.toString(db.getDecryptedXML()));

        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        db.write(credentials, new Serializer(bos), null, (level, msg, t) ->
        {
        });

        final byte[] actual = bos.toByteArray();
        byte[] expected;
        try ( InputStream in = resource.createInputStream() )
        {
            expected = in.readAllBytes();
        }

        final int len = Math.min(expected.length,actual.length);
        int equalBytesCount=0;
        for ( int i = 0 ; i < len ; i++ ) {
            if ( expected[i] != actual[i] ) {
                break;
            }
            equalBytesCount++;
        }
        System.out.println("Equal bytes: "+equalBytesCount);

        if ( expected.length != actual.length ) {
            fail("Array lengths differ, expected "+expected.length+" but got "+actual.length);
        }
        assertArrayEquals(expected, actual);

        final XmlPayloadView view1 = new XmlPayloadView(db);
        final EntryGroup group = view1.getGroups().get(0);
        final Entry entry1 = group.getEntryByTitle("Entry #1").get();
        final Entry entry2 = group.getEntryByTitle("Entry #2").get();

        final KeyValueItem<?> item1 = entry1.item("Password").get();
        assertNotNull(item1);
        System.out.println("Value: "+item1.valueProtected);

        final KeyValueItem<?> item2 = entry2.item("Password").get();
        assertNotNull(item2);
        System.out.println("Value: "+item2.valueProtected);

        assertFalse( item1.valueProtected  );
        assertFalse( item2.valueProtected );

        String password1 = ((StringKeyValueItem) item1).value;
        String password2 = ((StringKeyValueItem) item2).value;

        assertEquals("testpassword1", password1 );
        assertEquals("testpassword2", password2 );
    }
}