# keepassmerge

Java classes & command-line tool for reading, writing and merging KDBX 3.1 and KDBX 4.0 files.

I mostly build this to scratch my own itch, namely the fact that I've been using KeePassX on various devices (desktop,laptop,at work,etc.)
but never really felt much of an urge to upload the .kdbx file to some "free" file hoster to be able to share the same 
file across all those devices...I have little trust in the security provided by those.

As is to be expected, over time the files on each device started to diverge more and more, up to the point where I had to sometimes 
reset my password for some service because the "right" KeePassX file with the corresponding password was on a different device...

To finally have my cake and eat it, I wrote Java code to read,merge and write .kdbx files (both KDBX v3.1 and KDBX 4.0) and integrated it into a
web application that I'm running on my own physical server. The command-line tool is working but mostly exists because I wanted something
to test-drive the backend code before starting to work on the web application.

> While this tool works fine for me, you're hereby strongly advised to do as I do and keep
> around at least one more backup of a known-good .kdbx file in a safe location, just
> in case my tool screws up your files, your harddrive dies or your house burns down.

## Stand-alone use

Here's a short usage example. I intentionally tried to not be specific about what the XML payload actually contains as a lot of programs read/write .kdbx files and they all tend to add their own custom stuff/extensions to the files.

My code uses a XmlPayloadView class that is a thin wrapper around the underlying XML document and just provides some convenience methods for making the XML access slightly less painful.

```java
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
```


## Requirements (running)

Java >= 17

## Requirements (building)

Java >= 17
Maven >= 3.8.1

## Building

```mvn clean package```

This will generate two artifacts, the command-line client in core/target/keepassmerge.jar and a Java web application (WAR) file 
in webapp/target/keepassweb.war

## Using the command-line application

Passwords used for decrypting/encrypting the .kdbx files are read by trying the following places:

1. Read from the console unless the program is run in a non-interactive shell
2. Read from the "password" system property ( so you'd pass this as -Dpassword=... to the JVM)
3. Read from the "KPX_PASSWORD" environment variable

Note that obviously password sources 2. and 3. only make sense when operating on multiple files that all use the same password.

```
user@host $ java -jar core/target/keepassmerge.jar 

Usage: [-v|--verbose] [-d|--debug] <command> [command arguments]

Supported commands:


dumpxml [--decrypt-protected] <file> - dumps the XML payload

merge [--auto-adjust-rounds <milliseconds>] <src1> <src2> <...> <destination file> - combine data from multiple files
```

So to combine multiple files you'd run something like

```
java -jar core/target/keepassmerge.jar  file1.kdbx file2.kdbx output.kdbx
```
It's an error to specify any file more than once ; merging will also fail if the output file already exists. You can use the 
'--auto-adjust-rounds' to adjust the number of 'rounds' so that deriving the master key takes at least the given amount of time.
This is useful to make brute-forcing the file's password harder.

### How combining files currently works

- I'm only actually looking at the minimum amount of XML payload I can get away with (mostly because I'm lazy but also because I want to avoid having to update my application every time the .kdbx file format changes) and just copy stuff between the XML documents
- 'Combining' files is done by just looking for entries/groups with the same UUID (or same name/title, if no UUID match was found) and keeping the one with the latest modification date (so if you're merging files from computers whose clock is off, bad things will happen...make sure to run NTP everywhere)
- The merge algorithm will use the database file with the most entries as the merge target
- TODO: I'm currently *not* merging groups missing from the merge target. You'll get a warning when trying to merge files that have different groups

## Known Issues 

- I've only implemented using AES for the outer encryption and Salsa20/ChaCha for the inner encryption as this is KeePassX / KeePassXC use by default
- I don't use anything except the default "Root" group - the code responsible for merging will crash if you any other groups ("Recycle Bin" is fine as it will get ignored)
- Automatically coming up with the number of KDF rounds needed to hit a certain runtime (like KeePassXC for example does) is currently broken as my simple code was assuming a linear slow-down/speed-up when changing the number of rounds. This holds true for AES but very much falls apart for Argon2 so this functionality is currently broken for any KDF that is not AES.

## TODO

- add support for TwoFish / ChaCha20 outer encryption
- add support for more KDFs
- add support for merging entries in groups other than "Root" as well
- clean up code / API

# web application

The web application consists of a single page (build with the excellent Apache Wicket) that keeps a single
.kdbx (the master file) on the web server and lets you

- download the master file
- upload & then merge one or more .kdx files into the master file
- view an audit log of all download and merge operations (the log is stored in a single PostgreSQL table)
- receive an e-mail whenever the master file was downloaded or changed

I've secured the application using SSL client authentication, additionally downloading the file and merging files (for obvious reasons) requires you to enter the master file's password. 

I'm thinking about storing the master file password encrypted on the server instead and have the user provide a password that is then used to decrypt the master password ..but as I'm using Let's Encrypt certificates and rather strict SSL settings I'm not so scared of someone listening in on the password transmission.

The web application is loading it's configuration from the classpath, so in case of tomcat you'll need to put a 'keePassMerge.properties' file inside the ${catalina.home}/libs folder.

A sample file is contained in the /config folder of this repository, you'll need to adjust it to suit your own setup.

The PostgreSQL SQL files to setup the database are contained in the /sql folder.

Setting up SSL client authentication for Tomcat is "slightly" more involved so I'm going to be lazy and just point you to google search...

If you did everything correctly, you shoud be able to navigate to "https://your.server/keepassweb" and be greeted with something like this:

![Screenshot](https://github.com/toby1984/keepassmerge/blob/master/screenshot.png)
