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
import de.codesourcery.keepass.core.datamodel.UUID;
import de.codesourcery.keepass.core.datamodel.*;
import de.codesourcery.keepass.core.util.Logger;
import de.codesourcery.keepass.core.util.LoggerFactory;
import de.codesourcery.keepass.core.util.XmlHelper;
import org.apache.commons.lang3.Validate;
import org.w3c.dom.*;

import javax.xml.xpath.XPathExpression;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.function.Function;
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

    private static final Function<String,ZonedDateTime> TIMESTAMP = value -> ZonedDateTime.from( DateTimeFormatter.ISO_DATE_TIME.parse(value));
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

    final XPathExpression XPATH_HEADER_HASH = XmlHelper.xpath("/KeePassFile/Meta/HeaderHash");
    final XPathExpression XPATH_MEMORYPROTECTION = XmlHelper.xpath("/KeePassFile/Meta/MemoryProtection");
    final XPathExpression XPATH_GROUP_EXPR = XmlHelper.xpath("//Group");
    final XPathExpression XPATH_GROUP_NAME_EXPR = XmlHelper.xpath("Name/text()");
    final XPathExpression XPATH_GROUP_UUID_EXPR = XmlHelper.xpath("UUID/text()");

    final XPathExpression XPATH_ENTRY_EXPR = XmlHelper.xpath("Entry");
    final XPathExpression XPATH_ENTRY_UUID_EXPR = XmlHelper.xpath("UUID/text()");
    final XPathExpression XPATH_STRING_KEY_VALUE_EXPR = XmlHelper.xpath("String");

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
                    final MemoryProtection.ProtectedItem item = MemoryProtection.ProtectedItem.lookupByKeyName(keyNode.getTextContent());
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
                }
            }
        }
        if ( ! valuesToProtect.isEmpty() )
        {
            progressCallback.info("Encrypting "+valuesToProtect.size()+" payload values.");
            final Function<byte[], byte[]> cipher = database.createStreamCipher();
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
        result.times = parseTimes( XmlHelper.directChild(node, "Times") );

        final Iterator<Node> it = XmlHelper.evalNodeIterator(XPATH_STRING_KEY_VALUE_EXPR, node);
        while ( it.hasNext() ) {
            result.add( parseKeyValueItem(result, it.next() ) );
        }
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

    /**
     * Merges all missing or more recent {@link Entry entries} (based on UUID comparison)
     * into this XML payload.
     * 
     * @param other provides entries to merge with
     * @return <code>true</code> if this payload has been changed
     */
    public boolean merge(XmlPayloadView other, Logger progressCallback) {

        LOG.info("Merging " + other.database.resource + " into "+this.database.resource);

        boolean xmlPayloadChanged = false;
        final Document document = this.database.getDecryptedXML();
        final Document otherDocument = other.database.getDecryptedXML();
        final List<EntryGroup> existingGroups = getGroups();

        progressCallback.info("Merging "+other.database.resource+" into "+this.database.resource);

        for ( EntryGroup newGroup : other.getGroups() )
        {
            if ( newGroup.database.resource.isSame( this.database.resource ) ) {
                throw new IllegalArgumentException("Refusing to merge entries originating from the same source file");
            }
            Optional<EntryGroup> existingGroup = existingGroups.stream().filter(x -> x.uuid.equals(newGroup.uuid) ).findFirst();
            if (existingGroup.isEmpty()) {
                existingGroup = existingGroups.stream().filter(x -> x.name.equals(newGroup.name) ).findFirst();
                if ( existingGroup.isEmpty() )
                {
                    // TODO: Support adding new groups
                    // throw new RuntimeException("Sorry, adding new groups is currently not implemented");
                    progressCallback.error("Sorry, adding new groups is currently not implemented, offending group: " + newGroup.name);
                    LOG.error("Sorry, adding new groups to " + this.database.resource + " is currently not implemented");
                    LOG.error("Offending group: '" + newGroup.name + "' (" + newGroup.uuid + ")");
                    LOG.error("Already in destination:");
                    getGroups().forEach(g -> LOG.error("GOT '" + g.name + "' (" + g.uuid + ")"));
                    continue;
                }
            }
            final Collection<Entry> existingEntries = existingGroup.get().entries.values();
            for ( Entry newEntry : newGroup.entries.values() )
            {
                List<Entry> matches = existingEntries.stream().filter(e -> e.uuid.equals(newEntry.uuid)).collect(Collectors.toList());
                if (matches.isEmpty())
                {
                    // found no entry with matching UUID, search again using entry title
                    matches = existingEntries.stream().filter(e -> e.getTitle().equals(newEntry.getTitle())).collect(Collectors.toList());
                    if ( matches.isEmpty() )
                    {
                        progressCallback.info("Adding new entry for '" + newEntry.getTitle() + "' (last_modification: " + newEntry.times.lastModificationTime + ")");
                        if (Constants.DEBUG_MERGING)
                        {
                            LOG.info("Adding " + newEntry + " to " + this.database.resource);
                        }
                        final Document newDoc = newEntry.group.database.getDecryptedXML();
                        final Optional<Node> toClone = getEntryNode(newDoc, newEntry);
                        if (toClone.isEmpty())
                        {
                            // should never happen
                            throw new RuntimeException("Internal error, failed to find XML node for " + newEntry + " in its source database???");
                        }
                        final Node cloned = toClone.get().cloneNode(true);
                        document.adoptNode(cloned);
                        final Optional<Node> groupNode = getGroupNode(document, existingGroup.get().uuid);
                        if (groupNode.isEmpty())
                        {
                            throw new RuntimeException("Internal error, failed to find XML node for existing group ?");
                        }
                        groupNode.get().appendChild(cloned);
                        xmlPayloadChanged = true;
                        continue;
                    } else {
                        progressCallback.warn("Locating entry with UUID "+newEntry.uuid+" failed but using title '" + newEntry.getTitle() + "' succeeded.");
                    }
                }

                if ( matches.size() > 1 ) {
                    throw new RuntimeException("Currently not supported - found multiple entries with title '"+newEntry.getTitle()+"' in "+this.database);
                }

                final Entry existingEntry = matches.get(0);
                if ( newEntry.times.lastModificationTime.isAfter(existingEntry.times.lastModificationTime) )
                {
                    progressCallback.info("Replacing entry " + existingEntry.uuid + " ('" + existingEntry.getTitle() + "')" +
                                                " from " + existingEntry.times.lastModificationTime + " with entry "
                                                + newEntry.getTitle() + " , modified on " + newEntry.times.lastModificationTime);

                    if ( Constants.DEBUG_MERGING )
                    {
                        LOG.info("Updating " + existingEntry.uuid + " for " + existingEntry.getTitle() + ", " +
                                     "last modified on " + existingEntry.times.lastModificationTime + " while newer one is from "
                                     + newEntry.times.lastModificationTime);
                    }
                    updateEntry(document, existingEntry, otherDocument, newEntry);
                    xmlPayloadChanged = true;
                } else {
                    if ( Constants.DEBUG_MERGING )
                    {
                        LOG.info("Keeping " + existingEntry.uuid + " for " + existingEntry.getTitle());
                    }
                }
            }
        }

        if ( xmlPayloadChanged )
        {
            progressCallback.info("Merge target has been updated.");
            maybeEncryptPayloadValues(document, progressCallback);
            setXmlPayload(document, Constants.DEBUG_MERGING);
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

    private void updateEntry(Document targetDocument,Entry entryToReplace, Document sourceDocument, Entry newEntry)
    {
        Node targetNode = getEntryNode(targetDocument,entryToReplace)
                              .orElseThrow( () -> new RuntimeException("Found no entry node with " +
                                                                           "group "+entryToReplace.group+
                                                                           " and entry "+entryToReplace+" in "+
                                                                           database.resource ));

        final Node parent = targetNode.getParentNode();

        final Node historyNode = XmlHelper.directChild(targetNode,"History");

        final Node newNode = getEntryNode(sourceDocument,newEntry).map(x->x.cloneNode(true))
                              .orElseThrow( () -> new RuntimeException("Found no entry node with " +
                                                                           "group "+newEntry.group+
                                                                           " and entry "+newEntry+" in "+
                                                                           newEntry.group.database.resource ));

        targetDocument.adoptNode(newNode);
        parent.replaceChild(newNode,targetNode);

        // the next line is needed to avoid some weird
        // crash inside historyNode.appendChild() because
        // somehow the replaceChild() operation did not set the
        // parent NODE of targetNode to NULL so a sanity check
        // that tries to prevent cyclic references inside the tree
        // trips
        targetNode = targetNode.cloneNode(true);

        final NodeList children = historyNode.getChildNodes();
        for ( int i = 0 ; i < children.getLength() ; i++ ) {
            final Node n = children.item(i);
            if ( n.getNodeType() != Node.ELEMENT_NODE || ! "Entry".equals( n.getNodeName() ) ) {
                continue;
            }
            final Entry entry = parseEntry(n);
            if ( entry.times.lastModificationTime.isAfter(newEntry.times.lastModificationTime ) ) {
                historyNode.insertBefore(targetNode,n);
                return;
            }
        }
        historyNode.appendChild(targetNode);
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

    private Times parseTimes(Node node) {
        Times result = new Times();
        result.lastModificationTime = XmlHelper.directChild(node,"LastModificationTime",TIMESTAMP);
        result.creationTime = XmlHelper.directChild(node,"CreationTime",TIMESTAMP);
        result.lastAccessTime = XmlHelper.directChild(node,"LastAccessTime",TIMESTAMP);
        result.expiryTime = XmlHelper.directChild(node,"ExpiryTime",TIMESTAMP);
        result.expires= XmlHelper.directChild(node,"Expires",BOOLEAN);
        result.usageCount = XmlHelper.directChild(node,"UsageCount",INTEGER);
        result.locationChanged = XmlHelper.directChild(node,"LocationChanged",TIMESTAMP);
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

    public int getEntryCount() {
        return (int) getGroups().stream().mapToLong(grp->grp.entries().count()).sum();
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
            cipher = database.createStreamCipher();
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
}