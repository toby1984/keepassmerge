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
package de.codesourcery.keepass.core.fileformat;

import de.codesourcery.keepass.core.Constants;
import de.codesourcery.keepass.core.datamodel.Entry;
import de.codesourcery.keepass.core.datamodel.EntryGroup;
import de.codesourcery.keepass.core.datamodel.KeyValueItem;
import de.codesourcery.keepass.core.datamodel.MemoryProtection;
import de.codesourcery.keepass.core.datamodel.Meta;
import de.codesourcery.keepass.core.datamodel.StringKeyValueItem;
import de.codesourcery.keepass.core.datamodel.Times;
import de.codesourcery.keepass.core.datamodel.UUID;
import de.codesourcery.keepass.core.util.Endian;
import de.codesourcery.keepass.core.util.Logger;
import de.codesourcery.keepass.core.util.LoggerFactory;
import de.codesourcery.keepass.core.util.Misc;
import de.codesourcery.keepass.core.util.Version;
import de.codesourcery.keepass.core.util.XmlHelper;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.xpath.XPathExpression;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Provides a bi-directiona, mutable view of a
 * KeePass file's XML payload.
 *
 * Any changes the the XML view will automatically
 * update the wrapped <code>Database</code> object.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class XmlPayloadView
{
    private static final Logger LOG = LoggerFactory.getLogger( XmlPayloadView.class );

    private static final Pattern KDBX3_TIMESTAMP_PATTERN = Pattern.compile( "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}.+$");

    // KDBX v4 format
    // "All times are now stored as Base64 string of the Int64 number of seconds elapsed since 0001-01-01 00:00 UTC."
    private static final ZonedDateTime KDBX4_TIMESTAMP_REFERENCE =
        ZonedDateTime.of( 1, 1, 1, 0, 0, 0, 0, ZoneId.of( "UTC" ) );

    private static final Function<String,ZonedDateTime> TIMESTAMP_KDBX3 = value -> ZonedDateTime.from( DateTimeFormatter.ISO_DATE_TIME.parse(value));

    // KDBX v4 format
    // "All times are now stored as Base64 string of the Int64 number of seconds elapsed since 0001-01-01 00:00 UTC."
    private static final Function<String,ZonedDateTime> TIMESTAMP_KDBX4 = value ->
    {
        final byte[] secondsArray = Base64.getDecoder().decode( value );
        final long elapsedSeconds = Endian.LITTLE.readLong( secondsArray, 0 );
        if ( elapsedSeconds < 0 ) {
            throw new RuntimeException( "Seconds since 0001-01-001 00:00:00 UTC timestamp overflowed: " + elapsedSeconds );
        }
        return KDBX4_TIMESTAMP_REFERENCE.plusSeconds( elapsedSeconds ).withZoneSameInstant( ZoneId.systemDefault() );
    };

    private static final Function<String,Boolean> BOOLEAN = XmlPayloadView::boolFromString;
    private static final Function<String,Integer> INTEGER = Integer::parseInt;

    public static final String ATTR_IS_PROTECTED = "Protected";
    private static final String ATTR_VALUE_TRUE = "True";
    private static final String ATTR_VALUE_FALSE = "False";

    public static boolean boolFromString(String value) {
        return ATTR_VALUE_TRUE.equalsIgnoreCase(value);
    }

    public static  String boolToString(boolean value) {
        return value ? ATTR_VALUE_TRUE : ATTR_VALUE_FALSE;
    }

    // note: Not present in file format KDBX 4.x and upwards as those use HMAC-SHA256 to check integrity
    final XPathExpression XPATH_HEADER_HASH = XmlHelper.xpath("/KeePassFile/Meta/HeaderHash");

    final XPathExpression XPATH_MEMORYPROTECTION = XmlHelper.xpath("/KeePassFile/Meta/MemoryProtection");
    final XPathExpression XPATH_GROUP_EXPR = XmlHelper.xpath("//Group");
    final XPathExpression XPATH_GROUP_NAME_EXPR = XmlHelper.xpath("Name/text()");
    final XPathExpression XPATH_GROUP_UUID_EXPR = XmlHelper.xpath("UUID/text()");

    final XPathExpression XPATH_ENTRY_EXPR = XmlHelper.xpath("Entry");
    final XPathExpression XPATH_ENTRY_UUID_EXPR = XmlHelper.xpath("UUID/text()");
    final XPathExpression XPATH_STRING_KEY_VALUE_EXPR = XmlHelper.xpath("String");

    final XPathExpression XPATH_HISTORY_ENTRY_TIMESEXPR = XmlHelper.xpath("History/Entry/Times");
    final XPathExpression XPATH_TIMES_EXPR = XmlHelper.xpath("Times");

    public final Database database;

    public XmlPayloadView(Database db) {
        Validate.notNull(db, "dbn must not be null");
        this.database = db;
    }

    public byte[] getHeaderHash()
    {
        final Document xml = database.getDecryptedXML();
        final Node node = XmlHelper.unique( XmlHelper.eval( XPATH_HEADER_HASH, xml ) ).orElseThrow(() -> new RuntimeException("XML contains no header hash?"));
        return Base64.getDecoder().decode(node.getTextContent());
    }

    public void setHeaderHash(byte[] hash)
    {
        Validate.notNull(hash, "hash must not be null");
        Validate.isTrue(hash.length>0);

        if ( getAppVersion().major() >= 4 ) {
            throw new UnsupportedOperationException( "KDBX4 file format stores header hash differently" );
        }

        final Document xml = database.getDecryptedXML();

        final Node node = XmlHelper.unique( XmlHelper.eval( XPATH_HEADER_HASH, xml ) ).orElseThrow(() -> new RuntimeException("XML contains no header hash?"));
        final String oldValue = node.getTextContent();
        final String newValue = Base64.getEncoder().encodeToString(hash);
        LOG.info("setHeaderHash(): Changing header hash "+oldValue+" -> "+newValue);
        node.setTextContent( newValue );
        setXmlPayload(xml,false);
    }

    public Meta getMeta() {
        return getMeta(database.getDecryptedXML());
    }

    public Meta getMeta(Document doc)
    {
        final Iterator<Node> it = XmlHelper.evalNodeIterator(XPATH_MEMORYPROTECTION, doc);
        final Meta meta = new Meta();
        if ( it.hasNext() ) {
            final Node memoryProtection = it.next();
            meta.memoryProtection.setProtectionEnabled(MemoryProtection.ProtectedItem.NOTES, XmlHelper.directChild(memoryProtection, "ProtectNotes", BOOLEAN));
            meta.memoryProtection.setProtectionEnabled(MemoryProtection.ProtectedItem.TITLE, XmlHelper.directChild(memoryProtection, "ProtectTitle", BOOLEAN));
            meta.memoryProtection.setProtectionEnabled(MemoryProtection.ProtectedItem.USERNAME, XmlHelper.directChild(memoryProtection, "ProtectUserName", BOOLEAN));
            meta.memoryProtection.setProtectionEnabled(MemoryProtection.ProtectedItem.PASSWORD, XmlHelper.directChild(memoryProtection, "ProtectPassword", BOOLEAN));
            meta.memoryProtection.setProtectionEnabled(MemoryProtection.ProtectedItem.URL, XmlHelper.directChild(memoryProtection, "ProtectURL", BOOLEAN));
            meta.memoryProtection.setProtectionEnabled(MemoryProtection.ProtectedItem.NOTES, XmlHelper.directChild(memoryProtection, "ProtectNotes", BOOLEAN));
            if ( it.hasNext() ) {
                throw new IllegalStateException("More than one <MemoryProtection/> section?");
            }
        }
        return meta;
    }

    /**
     * Make sure all payload values are either encrypted or not according to the
     * &lt;MemoryProtection/&gt; section in the file's meta information and fix those that need it.
     *
     * @param decryptedXml XML with all payload values DECRYPTED (method will throw if it finds any encrypted values)
     * @param progressCallback
     * @return <code>true</code> if the input XML has been changed because values needed decryption/encryption
     */
    public boolean maybeEncryptPayloadValues(Document decryptedXml , Logger progressCallback)
    {
        final boolean innerEncryptionEnabled = database.isInnerEncryptionEnabled();

        // inner encryption is applied via a stream cipher,
        // so all entries need to be processed at once
        // in the order in which they occur inside the XML

        final XPathExpression allEntries = XmlHelper.xpath("//Entry");

        final MemoryProtection memoryProtection = getMeta(decryptedXml).memoryProtection;

        final List<Element> valuesToProtect = new ArrayList<>();
        for ( Node entryNode : XmlHelper.evalIterable(allEntries, decryptedXml ) )
        {
            for (Node child : XmlHelper.asIterable(entryNode.getChildNodes()))
            {
                if (child.getNodeType() == Node.ELEMENT_NODE && "String".equals(child.getNodeName()))
                {
                    final Node keyNode = XmlHelper.directChild(child, "Key");
                    final Optional<MemoryProtection.ProtectedItem> optItem = MemoryProtection.ProtectedItem.lookupByKeyName( keyNode.getTextContent() );
                    optItem.ifPresent( item -> {
                        final Element valueNode = (Element) XmlHelper.directChild(child, "Value");
                        final boolean valueIsProtected = boolFromString(valueNode.getAttribute(ATTR_IS_PROTECTED));
                        final boolean protEnabled = memoryProtection.isProtectionEnabled(item);
                        if ( valueIsProtected )
                        {
                            if ( ! innerEncryptionEnabled )
                            {
                                throw new RuntimeException("Internal error - inner encryption is not enabled but document contains encrypted payload values");
                            }
                            throw new RuntimeException("Internal error - value is protected but should've been decrypted by Database#getXml(boolean) call");
                        }
                        if (protEnabled) {
                            valuesToProtect.add( valueNode );
                        }
                    });
                }
            }
        }
        if ( ! valuesToProtect.isEmpty() )
        {
            progressCallback.info("Encrypting "+valuesToProtect.size()+" payload values.");
            final Function<byte[], byte[]> cipher = database.createStreamCipher(true);
            for ( Element valueNode : valuesToProtect )
            {
                valueNode.setAttribute(ATTR_IS_PROTECTED, XmlPayloadView.boolToString(true ));
                final byte[] plainText = valueNode.getTextContent().getBytes(StandardCharsets.UTF_8);
                final byte[] cipherText = cipher.apply(plainText );
                valueNode.setTextContent(Base64.getEncoder().encodeToString(cipherText));
            }
            return true;
        }
        return false;
    }

    private EntryGroup parseEntryGroup(Node node) {

        Validate.notNull(node, "node must not be null");

        final String name = XmlHelper.evalString(XPATH_GROUP_NAME_EXPR, node);
        final String uuid = XmlHelper.evalString(XPATH_GROUP_UUID_EXPR, node);
        final EntryGroup group = new EntryGroup(name, uuid(uuid) );
        group.times = parseTimes( XmlHelper.directChild(node, "Times" ) );
        final Iterator<Node> nodes = XmlHelper.evalNodeIterator(XPATH_ENTRY_EXPR, node);
        while( nodes.hasNext() ) {
            final Node entryNode = nodes.next();
            group.add(parseEntry(entryNode));
        }
        group.database = database;
        return group;
    }

    private Entry parseEntry(Node node)
    {
        final UUID uuid = uuid( XmlHelper.evalString(XPATH_ENTRY_UUID_EXPR, node) );

        final Entry result = new Entry(uuid);
        final Iterator<Node> it = XmlHelper.evalNodeIterator(XPATH_STRING_KEY_VALUE_EXPR, node);
        while ( it.hasNext() ) {
            result.add( parseKeyValueItem(result, it.next() ) );
        }
        result.times = parseTimes( XmlHelper.directChild(node, "Times") );
        LOG.debug("PARSED: "+result.getTitle());
        return result;
    }

    private KeyValueItem<?> parseKeyValueItem(Entry owningEntry, Node node) {
        final String name = node.getNodeName();
        if ( ! "String".equals(name) ) {
            throw new RuntimeException("Internal error, key/value node <" + name + "> is currently not implemented");
        }
        boolean valueProtected = false;
        String key=null;
        String value=null;

        for ( Iterator<Node> it = XmlHelper.asIterator(node.getChildNodes()) ; it.hasNext() ; ) {
            final Node n = it.next();
            if ( n.getNodeType() != Node.ELEMENT_NODE ) {
                continue;
            }
            if ( "Key".equals( n.getNodeName() ) ) {
                key = n.getTextContent();
            } else if ( "Value".equals( n.getNodeName() ) ) {
                final String attrValue = ((Element) n).getAttribute(ATTR_IS_PROTECTED);
                valueProtected = boolFromString(attrValue);
                value = n.getTextContent();
            } else {
                throw new RuntimeException("Internal error, XML contained unexpected node '"+n.getNodeName()+"'");
            }
        }
        if ( key == null || value == null ) {
            throw new RuntimeException("Failed to parse key/value item");
        }
        final StringKeyValueItem item = new StringKeyValueItem(owningEntry, key, value);
        item.valueProtected = valueProtected;
        return item;
    }

    private Version getAppVersion() {
        return this.database.getAppVersion();
    }

    /**
     * Merges all missing or more recent {@link Entry entries} (based on UUID comparison)
     * into THIS XML payload.
     *
     * @param other provides entries to merge with
     * @return <code>true</code> if this payload has been changed
     */
    public boolean merge(XmlPayloadView other, Logger progressCallback) {

        final Version srcVersion = other.getAppVersion();
        final String msg = "Merging " + other.database.resource + " (" + srcVersion + ") into " + this.database.resource + " (" + getAppVersion() + ")";
        LOG.info( msg );

        final Document mergeDestination = this.database.getDecryptedXML();
        final Document mergeSource = other.database.getDecryptedXML();

        final List<EntryGroup> existingGroups = getGroups();

        progressCallback.info(msg);

        boolean xmlPayloadChanged = false;

        for ( EntryGroup groupFromSource : other.getGroups() )
        {
            if ( groupFromSource.database.resource.isSame( this.database.resource ) ) {
                throw new IllegalArgumentException("Refusing to merge entries originating from the same source file");
            }
            if ( "Recycle Bin".equals( groupFromSource.name ) ) {
                LOG.info("Ignoring group 'Recycle Bin'");
                continue;
            }
            Optional<EntryGroup> existingGroup = existingGroups.stream().filter(x -> x.uuid.equals(groupFromSource.uuid) ).findFirst();
            if (existingGroup.isEmpty()) {
                existingGroup = existingGroups.stream().filter(x -> x.name.equals(groupFromSource.name) ).findFirst();
                if ( existingGroup.isEmpty() )
                {
                    // TODO: Support adding new groups
                    // throw new RuntimeException("Sorry, adding new groups is currently not implemented");
                    progressCallback.error("Sorry, adding new groups is currently not implemented, offending group: " + groupFromSource.name);
                    LOG.error("Sorry, adding new groups to " + this.database.resource + " is currently not implemented");
                    LOG.error("Offending group: '" + groupFromSource.name + "' (" + groupFromSource.uuid + ")");
                    LOG.error("Already in destination:");
                    getGroups().forEach(g -> LOG.error("GOT '" + g.name + "' (" + g.uuid + ")"));
                    continue;
                }
            }
            final Collection<Entry> existingEntries = existingGroup.get().entries.values();
            for ( Entry entryFromSource : groupFromSource.entries.values() )
            {
                List<Entry> matches = existingEntries.stream().filter(e -> e.uuid.equals(entryFromSource.uuid)).collect(Collectors.toList());
                if (matches.isEmpty())
                {
                    // found no entry with matching UUID, search again using entry title
                    matches = existingEntries.stream().filter(e -> e.getTitle().equals(entryFromSource.getTitle())).collect(Collectors.toList());
                    if ( matches.isEmpty() )
                    {
                        // copy missing/new entry to destination
                        progressCallback.info("Adding new entry for '" + entryFromSource.getTitle() + "' (last_modification: " + entryFromSource.times.lastModificationTime + ")");
                        if (Constants.DEBUG_MERGING)
                        {
                            LOG.info("Adding " + entryFromSource + " to " + this.database.resource);
                        }
                        final Document newDoc = entryFromSource.group.database.getDecryptedXML();
                        final Optional<Node> toClone = getEntryNode(newDoc, entryFromSource);
                        if ( toClone.isEmpty() )
                        {
                            // should never happen
                            throw new RuntimeException("Internal error, failed to find XML node for " + entryFromSource + " in its source database???");
                        }
                        final Node clonedEntry = toClone.get().cloneNode(true);
                        mergeDestination.adoptNode(clonedEntry);

                        // make sure to convert between V3 and V4 file format timestamps
                        if ( getAppVersion().major() != other.getAppVersion().major() )
                        {
                            final Consumer<Element> converter;
                            if ( getAppVersion().major() < 4 && other.getAppVersion().major() >= 4 ) {
                                // v4 -> v3 timestamp conversion needed
                                progressCallback.info( "Converting timestamps v4 -> v3" );
                                converter = XmlPayloadView::convertV4TimestampsToV3;
                            } else if ( getAppVersion().major() >= 4 && other.getAppVersion().major() < 4 ) {
                                // v3 -> v4 timestamp conversion needed
                                converter = XmlPayloadView::convertV3TimestampsToV4;
                                progressCallback.info( "Converting timestamps v3 -> v4" );
                            } else {
                                converter = null;
                            }
                            if ( converter != null ) {
                                // Convert <Times> of entry itself
                                final Node times = XmlHelper.directChild( clonedEntry, "Times" );
                                converter.accept( (Element) times );
                                // Convert <Times> of entry history (if any)
                                final Node history = XmlHelper.directChild( clonedEntry, "History" );
                                if ( history != null ) {

                                    XmlHelper.directChildren( history, "Entry" ).forEach( entry ->
                                    {
                                        final Node times2 = XmlHelper.directChild( entry, "Times" );
                                        converter.accept( (Element) times2 );
                                    });
                                }
                            }
                        }

                        final Optional<Node> groupNode = getGroupNode(mergeDestination, existingGroup.get().uuid);
                        if (groupNode.isEmpty())
                        {
                            throw new RuntimeException("Internal error, failed to find XML node for existing group ?");
                        }
                        groupNode.get().appendChild(clonedEntry);
                        xmlPayloadChanged = true;
                        continue;
                    }
                    progressCallback.warn("Locating entry with UUID "+entryFromSource.uuid+" failed but using title '" + entryFromSource.getTitle() + "' succeeded.");
                }

                if ( matches.size() > 1 ) {
                    throw new RuntimeException("Currently not supported - found multiple entries with title '"+entryFromSource.getTitle()+"' in "+this.database);
                }

                final Entry entryFromDestination = matches.get(0);
                if ( entryFromSource.times.lastModificationTime.isAfter(entryFromDestination.times.lastModificationTime) )
                {
                    progressCallback.info("Replacing entry " + entryFromDestination.uuid + " ('" + entryFromDestination.getTitle() + "')" +
                        " from " + entryFromDestination.times.lastModificationTime + " with entry "
                        + entryFromSource.getTitle() + " , modified on " + entryFromSource.times.lastModificationTime);

                    if ( Constants.DEBUG_MERGING )
                    {
                        LOG.info("Updating " + entryFromDestination.uuid + " for " + entryFromDestination.getTitle() + ", " +
                            "last modified on " + entryFromDestination.times.lastModificationTime + " while newer one is from "
                            + entryFromSource.times.lastModificationTime);
                    }
                    updateEntry(mergeDestination, entryFromDestination, mergeSource, entryFromSource,srcVersion);
                    xmlPayloadChanged = true;
                } else {
                    if ( Constants.DEBUG_MERGING )
                    {
                        LOG.info( "Keeping " + entryFromDestination.uuid + " for " + entryFromDestination.getTitle() + " as " +
                            entryFromDestination.times.lastModificationTime + " is more recent than " + entryFromSource.times.lastModificationTime );
                    }
                }
            }
        }

        if ( xmlPayloadChanged )
        {
            progressCallback.info("Merge target has been updated.");
            maybeEncryptPayloadValues(mergeDestination, progressCallback);
            setXmlPayload(mergeDestination, Constants.DEBUG_MERGING);
        }
        return xmlPayloadChanged;
    }

    public void setXmlPayload(Document document) {
        setXmlPayload(document, false);
    }

    private void setXmlPayload(Document document,boolean logXml)
    {
        final String newXml = XmlHelper.toString(document);
        if ( logXml )
        {
            LOG.debug("=== UPDATED XML ===");
            LOG.debug(newXml);
        }
        final PayloadBlock xmlPayload = this.database.getBlock(PayloadBlock.BLOCK_ID_PAYLOAD).get();
        xmlPayload.setData(newXml.getBytes(StandardCharsets.UTF_8));
    }

    public static ZonedDateTime stringToTimestamp(String s, Version appVersion) {
        if ( appVersion.major() < 4 )
        {
            return TIMESTAMP_KDBX3.apply( s );
        }
        try
        {
            return TIMESTAMP_KDBX4.apply( s );
        } catch(Exception e) {
            throw new RuntimeException( e.getMessage() + " : '" + s + "'", e );
        }
    }

    public String timestampToString(ZonedDateTime ts, Version appVersion)
    {
        if ( appVersion.major() < 4 ) {
            return DateTimeFormatter.ISO_DATE_TIME.format( ts );
        }
        final Duration duration = Duration.between( KDBX4_TIMESTAMP_REFERENCE, ts );
        final byte[] binaryLittleEndian = Endian.LITTLE.toLongBytes( duration.getSeconds() );
        return Base64.getEncoder().encodeToString( binaryLittleEndian );
    }

    /**
     * This method will either completely replace the older entry with the more recent one (if file versions are identical) or will
     * just copy some basic attributes from the more recent version over to the other (if file versions are different).
     *
     * @param mergeDestination
     * @param entryToUpdate
     * @param mergeSource
     * @param moreRecentEntry
     * @param sourceFileVersion
     */
    private void updateEntry(Document mergeDestination,Entry entryToUpdate, Document mergeSource, Entry moreRecentEntry,
                             Version sourceFileVersion)
    {
        Node targetNode = getEntryNode(mergeDestination,entryToUpdate)
            .orElseThrow( () -> new RuntimeException("Found no entry node with " +
                "group "+entryToUpdate.group+
                " and entry "+entryToUpdate+" in "+
                database.resource ));

        final Node parent = targetNode.getParentNode();

        final Node historyNode = XmlHelper.directChild(targetNode,"History");

        final Node moreRecentNode = getEntryNode(mergeSource,moreRecentEntry).map(x->x.cloneNode(true))
            .orElseThrow( () -> new RuntimeException("Found no entry node with " +
                "group "+moreRecentEntry.group+
                " and entry "+moreRecentEntry+" in "+
                moreRecentEntry.group.database.resource ));
        final boolean migrateWellKnownAttributesOnly = getAppVersion().major() != sourceFileVersion.major();

        final Node modHistoryEntry;
        if ( migrateWellKnownAttributesOnly )
        {
            // we're doing a merge between incompatible file formats ( v4 -> v3) so we're going to
            // only replace the values of a few well-known attributes that are supported by KeePass itself
            final String[] attributesToCopy = {"Notes","Password","Title","URL","UserName" };

            modHistoryEntry = moreRecentNode.cloneNode( true );
            mergeDestination.adoptNode( modHistoryEntry );

            if ( sourceFileVersion.hasMajorVersion( 3 ) ) {
                // convert ISO timestamps to weird V4 format

                // fix Entry/Times
                final Node times = XmlHelper.evalUnique( XPATH_TIMES_EXPR, modHistoryEntry ).get();
                convertV3TimestampsToV4( (Element) times );

                // fix Entry/History/Entry/Times
                XmlHelper.evalNodeStream( XPATH_HISTORY_ENTRY_TIMESEXPR, modHistoryEntry )
                    .forEach( match -> {
                        convertV3TimestampsToV4( (Element) match );
                    } );
            }

            for ( String attribute : attributesToCopy )
            {
                final Optional<String> moreRecentValue = getEntryValue( moreRecentNode, attribute );

                if ( moreRecentValue.isPresent() )
                {
                    final Optional<Node> destination = getEntryValueNode( targetNode, attribute );
                    if ( destination.isPresent() )
                    {
                        // update value of existing <Value> node
                        destination.get().setTextContent( moreRecentValue.get() );
                    }
                    else
                    {
                        // write new node
                        final Element attributeEntry = mergeDestination.createElement( "String" );
                        final Element key = mergeDestination.createElement( "Key" );
                        key.setTextContent( attribute );

                        final Element value = mergeDestination.createElement( "Value" );
                        value.setTextContent( moreRecentValue.get() );
                        attributeEntry.appendChild( key );
                        attributeEntry.appendChild( value);

                        // add right after last <Entry>
                        Element lastEntry = null;
                        for ( final Node node : XmlHelper.asIterable( targetNode.getChildNodes() ) )
                        {
                            if ( node instanceof Element e && "Entry".equals( e.getNodeName() ) ) {
                                lastEntry = e;
                            }
                        }
                        if ( lastEntry == null ) {
                            targetNode.appendChild( attributeEntry );
                        } else {
                            lastEntry.getParentNode().insertBefore( attributeEntry, lastEntry );
                        }
                    }
                } else {
                    // TODO: value is absent from source, make sure it's also absent from destination
                    //       and remove it if necessary
                    final Optional<Node> attrEntry  = getAttributeEntry( targetNode, attribute );
                    attrEntry.ifPresent( node -> node.getParentNode().removeChild( node ) );
                }
            }
        }
        else
        {
            // source and destination file formats use the same major version, just copy the XML node verbatim

            mergeDestination.adoptNode( moreRecentNode );
            parent.replaceChild( moreRecentNode, targetNode );

            // the next line is needed to avoid some weird
            // crash inside historyNode.appendChild() because
            // somehow the replaceChild() operation did not set the
            // parent NODE of targetNode to NULL so a sanity check
            // that tries to prevent cyclic references inside the tree
            // trips
            modHistoryEntry = targetNode.cloneNode(true);
        }

        // add new history entry to track our change
        final NodeList children = historyNode.getChildNodes();
        for ( int i = 0 ; i < children.getLength() ; i++ ) {
            final Node n = children.item(i);
            if ( n.getNodeType() != Node.ELEMENT_NODE || ! "Entry".equals( n.getNodeName() ) ) {
                continue;
            }
            final Entry entry = parseEntry(n);
            if ( entry.times.lastModificationTime.isAfter(moreRecentEntry.times.lastModificationTime ) ) {
                historyNode.insertBefore(modHistoryEntry,n);
                return;
            }
        }
        historyNode.appendChild(modHistoryEntry);
    }

    private static UUID uuid(String base64Value) {
        return new UUID( Base64.getDecoder().decode(base64Value) );
    }

    private Optional<Node> getGroupNode(Document document, UUID groupUUID)
    {
        final Function<UUID,String> uuidXPath = uuid -> "UUID[text()=\""+uuid.base64()+"\"]";
        final XPathExpression xpath = XmlHelper.xpath("/KeePassFile/Root/Group/" + uuidXPath.apply(groupUUID));
        final NodeList list = XmlHelper.eval(xpath, document);
        if ( list.getLength() != 1 ) {
            return Optional.empty();
        }
        return Optional.of(list.item(0).getParentNode());
    }

    private Times parseTimes(Node node)
    {
        final Function<String, ZonedDateTime> parser = x -> stringToTimestamp( x, getAppVersion() );
        final Times result = new Times();
        result.lastModificationTime = XmlHelper.directChild(node,"LastModificationTime", parser );
        result.creationTime = XmlHelper.directChild(node,"CreationTime", parser );
        result.lastAccessTime = XmlHelper.directChild(node,"LastAccessTime", parser );
        result.expiryTime = XmlHelper.directChild(node,"ExpiryTime", parser );
        result.expires= XmlHelper.directChild(node,"Expires",BOOLEAN);
        result.usageCount = XmlHelper.directChild(node,"UsageCount",INTEGER);
        result.locationChanged = XmlHelper.directChild(node,"LocationChanged", parser );
        return result;
    }

    private Optional<Node> getEntryNode(Document document,Entry entry)
    {
        final Function<UUID,String> uuidXPath = uuid -> "UUID[text()='"+uuid.base64()+"']";
        final String groupExpr = "/KeePassFile/Root/Group/" + uuidXPath.apply(entry.group.uuid)+"/..";

        final Optional<Node> groupNode = XmlHelper.unique(XmlHelper.eval(XmlHelper.xpath(groupExpr), document));

        if ( groupNode.isEmpty() ) {
            System.err.println("Found no match for '"+groupExpr+"'");
            return Optional.empty();
        }

        final String entryExpr = "./Entry/"+uuidXPath.apply(entry.uuid)+"/..";
        final Optional<Node> result = XmlHelper.unique(XmlHelper.eval(XmlHelper.xpath(entryExpr), groupNode.get()));
        if (result.isEmpty()) {
            System.err.println("Found no match for '"+entryExpr+"'");
            return Optional.empty();
        }
        return result;
    }

    private Optional<Node> getEntryValueNode(Node entry, String attribute)
    {
        final Optional<Node> match = getAttributeEntry( entry, attribute );
        return match.flatMap( node -> XmlHelper.optDirectChild( node, "Value" ) );
    }

    private Optional<String> getEntryValue(Node entry, String attribute)
    {
        return getEntryValueNode(entry, attribute).map( node -> {
            final String content = node.getTextContent();
            return content == null ? "" : content;
        } );
    }

    private Optional<Node> getAttributeEntry(Node entry, String attribute)
    {
        final Predicate<Node> hasMatchingKeyEntry = n ->
        {
            for ( final Node child : XmlHelper.asIterable( n.getChildNodes() ) )
            {
                if ( child instanceof Element e && "Key".equalsIgnoreCase( e.getTagName() ) && attribute.equals(  e.getTextContent() ) ) {
                    return true;
                }
            }
            return false;
        };

        final List<Element> elements = XmlHelper
            .asStream( entry.getChildNodes() )
            .filter( x -> x instanceof Element e && hasMatchingKeyEntry.test(e))
            .map( x -> (Element) x )
            .collect( Collectors.toList() );

        return switch( elements.size() ) {
            case 0 -> Optional.empty();
            case 1 -> Optional.of( elements.get( 0 ) );
            default -> throw new IllegalStateException( "Found multiple nodes for attribute '" + attribute+ "'" );
        };
    }

    public int getEntryCount() {
        return (int) getGroups().stream().mapToLong(grp->grp.entries().count()).sum();
    }

    public Optional<EntryGroup> getGroup(String title) {
        return getGroups().stream().filter( g -> title.equals( g.name) )
            .findFirst();
    }

    /**
     * Returns all entry groups.
     *
     * @return entry groups
     */
    public List<EntryGroup> getGroups()
    {
        return new XmlParser().parse();
    }

    private final class XmlParser {

        private final Function<byte[],byte[]> cipher;

        public XmlParser()
        {
            cipher = database.createStreamCipher(false);
        }

        private String decryptInner(String base64CipherText)
        {
            final byte[] bytes = Base64.getDecoder().decode(base64CipherText);
            final byte[] plainText = cipher.apply(bytes);
            return new String(plainText, StandardCharsets.UTF_8);
        }

        public List<EntryGroup> parse() {
            final List<EntryGroup> result = new ArrayList<>();

            final Document xml = database.getDecryptedXML();
            for ( Node groupNode : XmlHelper.evalIterable(XPATH_GROUP_EXPR, xml) ) {
                final EntryGroup group = parseEntryGroup(groupNode);
                for ( Entry e : group.entries.values() )
                {
                    LOG.trace("Processing entry '"+e.getTitle()+"'");
                    for ( KeyValueItem<?> item : e.items.values() )
                    {
                        if ( item.valueProtected )
                        {
                            LOG.trace("Decoding protected item '"+item.key+"'");
                            if (!(item instanceof StringKeyValueItem s))
                            {
                                throw new RuntimeException("Don't know how to un-protected item");
                            }
                            s.value = decryptInner( s.value );
                            s.valueProtected = false;
                        }
                    }
                }
                result.add(group);
            }
            return result;
        }
    }

    private static void convertV3TimestampsToV4(Element timesElement)
    {
        final Predicate<String> predicate = s -> KDBX3_TIMESTAMP_PATTERN.matcher( s ).matches();

        final Function<String,String> converter = input -> {
            final ZonedDateTime ts = TIMESTAMP_KDBX3.apply( input );
            long diffToRef = Duration.between( KDBX4_TIMESTAMP_REFERENCE, ts ).getSeconds();
            final byte[] binDate = Endian.LITTLE.toLongBytes( diffToRef );
            return Base64.getEncoder().encodeToString( binDate );
        };
        convertTimestamps( timesElement, predicate, converter );
    }

    private static void convertV4TimestampsToV3(Element timesElement)
    {
        final Predicate<String> predicate = Misc::isBase64;

        final Function<String,String> converter = input -> {
            final ZonedDateTime ts = TIMESTAMP_KDBX4.apply( input );
            return DateTimeFormatter.ISO_DATE_TIME.format( ts );
        };
        convertTimestamps( timesElement, predicate, converter );
    }

    private static void convertTimestamps(Element timesElement,Predicate<String> needsConversion,Function<String,String> converter)
    {
        for ( Node child : XmlHelper.asIterable( timesElement.getChildNodes() ) )
        {
            final String value = child.getTextContent();
            if ( StringUtils.isNotBlank(value) && needsConversion.test(value) )
            {
                child.setTextContent( converter.apply( value ) );
            }
        }
    }
}