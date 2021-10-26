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
import de.codesourcery.keepass.core.fileformat.XmlPayloadView;
import de.codesourcery.keepass.core.util.IResource;
import de.codesourcery.keepass.core.util.XmlHelper;
import org.w3c.dom.Document;

import javax.crypto.BadPaddingException;
import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.util.List;

public class Example
{
    public static void main(String[] args) throws IOException
    {
        if ( args.length != 1 )
        {
            throw new RuntimeException( "Expected a .kdbx filename" );
        }
        final String file = args[0];

        final char[] pwd = readPassword();

        // open database file
        // (this will decrypt the XML payload but NOT protected fields like passwords etc.
        //  inside the payload)
        final Database db;
        try
        {
            db = Database.read( List.of( Credential.password( pwd ) ), IResource.file( new File( file ) ) );
        }
        catch(BadPaddingException ex)
        {
            // thrown if the master password was wrong
            throw new RuntimeException( "Bad password" );
        }
        System.out.println("App version: "+db.getAppVersion());

        // print xml with all encrypted values in plain text
        final boolean decryptProtectedPayloadValues = true;
        final Document xml = db.getDecryptedXML( decryptProtectedPayloadValues );
        System.out.println( XmlHelper.toString( xml ) );

        // Loop over all groups & entries
        final XmlPayloadView xmlView = new XmlPayloadView( db );
        xmlView.getGroups().forEach( group -> {
            System.out.println("Found group "+group.name);
            group.entries().forEach( entry -> {
                System.out.println( "Got entry " + entry.getTitle() + " , last modified on " + entry.times.lastModificationTime );
            });
        });
    }

    private static char[] readPassword()
    {
        // read password from console
        // try reading from console
        final Console console = System.console();
        if ( console == null ) {
            throw new RuntimeException("Shell is non-interactive, cannot read password");
        }

        final String msg = "Please enter the password";

        // hint: at least on my Linux system, only the first readPassword() call worked
        // properly, the next one would include some leading ANSI sequences (draw rectangular area stuff)
        // that I couldn't get rid of
        final char[] pwd = Main.trim( Main.stripANSI( console.readPassword(msg) ) );
        if ( pwd.length == 0 ) {
            throw new RuntimeException("Aborted, you need to enter a password.");
        }
        return pwd;
    }
}
