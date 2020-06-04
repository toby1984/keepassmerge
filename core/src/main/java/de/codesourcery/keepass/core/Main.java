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
import de.codesourcery.keepass.core.util.*;
import org.apache.commons.lang3.StringUtils;
import org.w3c.dom.Document;

import javax.crypto.BadPaddingException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.*;

public class Main
{
    private static Logger LOG;

    private static void printHelp() {
        System.out.println();
        System.out.println("Usage: [-v|--verbose] [-d|--debug] <command> [command arguments]");
        System.out.println("\nSupported commands:\n\n");
        System.out.println("dumpxml [--decrypt-protected] <file> - dumps the XML payload\n");
        System.out.println("combine [--auto-adjust-rounds <milliseconds>] <src1> <src2> <...> <destination file> - combine data from multiple files");
        System.exit(1);
    }

    public static void main(String[] arguments) throws IOException, BadPaddingException
    {
        final List<String> args = new ArrayList<>(Arrays.asList(arguments));
        if ( args.removeIf( x -> "-h".equals(x) || "--help".equals(x) ) ) {
            printHelp(); // never returns
        }
        LoggerFactory.currentLevel = Logger.Level.INFO;
        if ( args.removeIf( x -> "-v".equals(x) || "--verbose".equals(x) ) ) {
            LoggerFactory.currentLevel = Logger.Level.DEBUG;
        }
        if ( args.removeIf( x -> "-d".equals(x) || "--debug".equals(x) ) ) {
            LoggerFactory.currentLevel = Logger.Level.TRACE;
        }
        LOG = LoggerFactory.getLogger(Main.class );

        if ( args.isEmpty() ) {
            printHelp(); // never returns
        }

        final String command = args.remove(0);
        switch( command )
        {
            /* ***********
             * Dump xml
             * ***********/
            case "dumpxml" -> {

                final boolean decrypt = args.removeIf( "--decrypt-protected"::equals);

                if ( args.size() != 1 ) {
                    throw new RuntimeException("Invalid command line - you need to specify a .kdbx database file");
                }

                final Database db = load(IResource.file(new File(args.get(0))));
                System.out.println(XmlHelper.toString(db.getDecryptedXML(decrypt)));
            }
            /* ***********
             * "Fix" files
             * This is just some hack to fix
             * a bug that would the inner payload
             * unencrypted even if <MemoryProtection/> would say
             * otherwise
             * ***********/
            case "fix" -> {

                if (args.size() != 2)
                {
                    System.err.println("Invalid command line, need source and target file");
                    printHelp(); // never returns
                }

                final File srcFile = new File(args.get(0));
                final File dstFile = new File(args.get(1));

                if ( isSameFile(args.get(0), args.get(1) ) )
                {
                    throw new RuntimeException("Invalid command line, source and destination must be different");
                }

                final Database src = load(IResource.file(srcFile) );
                final IResource res = IResource.file(dstFile);
                final XmlPayloadView view = new XmlPayloadView(src);
                final Document document = src.getDecryptedXML();
                if ( view.maybeEncryptPayloadValues(document, LOG) )
                {
                    view.setXmlPayload(document);
                    LOG.info("Writing fixed file to "+res);
                    try (Serializer s = new Serializer(res.createOutputStream(false)))
                    {
                        src.write( List.of(Credential.password(readPassword(res))), s, null, (level, msg, t) -> LOG.log(level, msg, t));
                    }
                } else {
                    LOG.info("Nothing to fix.");
                }
            }
            /* ***********
             * Merge files
             * ***********/
            case "combine" -> {

                Duration minKeyDerivationTime = null;
                final int idx = args.indexOf("--auto-adjust-rounds");
                if ( idx != -1 ) {
                    if ( idx+1 >= args.size() ) {
                        throw new RuntimeException("--auto-adjust-rounds requires an argument");
                    }
                    try {
                        minKeyDerivationTime = Duration.ofMillis(Integer.parseInt( args.get(idx+1 ) ) );
                        args.remove(idx);
                        args.remove(idx);
                    }
                    catch(Exception e) {
                        throw new RuntimeException("Invalid time in milliseconds: '"+args.get(idx+1));
                    }
                }

                if (args.size() < 2)
                {
                    System.err.println("Invalid command line, need at least one source and one destination file");
                    printHelp(); // never returns
                }

                final Map<String,Database> sources = new HashMap<>();
                File destination = null;
                for (int i = 0; i < args.size(); i++)
                {
                    final String file = args.get(i);
                    final Path path = Paths.get(file);
                    if ( sources.keySet().stream().anyMatch( x -> isSameFile(x, file ) ) ) {
                        throw new RuntimeException("Mentioning the file '"+file+"' more than once is not allowed");
                    }
                    if ( i != args.size()-1 )
                    {
                        final Database db = load(IResource.file(new File(file)));
                        sources.put(file, db);
                    } else {
                        destination = path.toFile();
                        if (destination.exists())
                        {
                            throw new IOException("Destination file " + destination.getAbsolutePath() + " already exists.");
                        }
                    }
                }
                final MergeHelper.MergeResult merged = MergeHelper.combine(sources.values(), (level, msg, t) -> {});
                if ( merged.mergedDatabaseChanged() || ! merged.mergedDatabase().resource.isSame(IResource.file(destination) ) )
                {
                    final char[] password = readPassword(merged.mergedDatabase().resource);

                    LOG.info("Writing result to " + destination.getAbsolutePath());
                    try (Serializer out = new Serializer(new FileOutputStream(destination)))
                    {
                        merged.mergedDatabase().write(List.of(Credential.password(password)), out, minKeyDerivationTime, (level, msg, t) -> {
                            //
                        });
                    }
                }
                else
                {
                    LOG.info("Merging produced no changes, nothing written.");
                }
            }
            default -> printHelp();  // never returns
        }
    }

    private static boolean isSameFile(String file1, String file2) {
        try
        {
            final File f1 = new File(file1);
            final File f2 = new File(file2);
            if ( f1.exists() && f2.exists() )
            {
                return Files.isSameFile(Paths.get(file1), Paths.get(file2));
            }
            return f1.getAbsolutePath().equals( f2.getAbsolutePath() );
        } catch (IOException e)
        {
            throw new RuntimeException(e);
        }
    }

    private static Database load(IResource resource) throws IOException, BadPaddingException
    {
        return load(resource, List.of(Credential.password(readPassword(resource))));
    }

    private static char[] readPassword(IResource file)
    {
        String env = System.getProperties().getProperty("password");
        if (env != null)
        {
            LOG.info("Using existing password from -Dpassword: " + StringUtils.repeat('*', env.length()));
            return env.toCharArray();
        }
        env = System.getenv("KPX_PASSWORD");
        if ( env != null )
        {
            LOG.info("Using existing password from KPX_PASSWORD: " + StringUtils.repeat('*', env.length()));
            return env.toCharArray();
        }

        final Console console = System.console();
        if ( console == null ) {
            throw new RuntimeException("Neither -Dpassword nor KPX_PASSWORD are set and the shell is non-interactive.");
        }

        final String msg = "Please enter the password for '"+file+"'";

        // hint: at least on my Linux system, only the first readPassword() call worked
        // properly, the next one would include some leading ANSI sequences (draw rectangular area stuff)
        // that I could'nt get rid of
        final char[] pwd = trim( stripANSI( console.readPassword(msg) ) );
        if ( pwd.length == 0 ) {
            throw new RuntimeException("Aborted, you need to enter a password.");
        }
        return pwd;
    }

    private static char[] stripANSI(char[] input)
    {
        if ( input == null ) {
            return new char[0];
        }
        final StringBuilder result = new StringBuilder();
        boolean ansiSequenceStarted = false;
        char lastCharacter = 'x';
        for (char c : input)
        {
            if (c == 27)
            {
                ansiSequenceStarted = true;
                continue;
            }
            if (ansiSequenceStarted)
            {
                if (c == lastCharacter)
                {
                    ansiSequenceStarted = false;
                }
            }
            else
            {
                result.append(c);
            }
        }
        return result.toString().toCharArray();
    }

    private static char[] trim(char[] input) {
        if ( input == null ) {
            return new char[0];
        }
        int start = 0;
        int end = input.length;
        for ( ; start < input.length && Character.isWhitespace(input[start] ) ; start++) {
        }
        for ( ; end > 0 && Character.isWhitespace(input[end-1] ) ; end--) {
        }
        return Arrays.copyOfRange(input,start,end);
    }

    public static Database load(IResource resource, List<Credential> credentials) throws IOException, BadPaddingException
    {
        final Database db = new Database();
        db.load(credentials, resource);
        return db;
    }
}