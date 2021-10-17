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
package de.codesourcery.keepass.core.util;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public class XmlHelper
{
    public static Document parse(String xml)
    {
        try
        {
            return createDocumentBuilder().parse(new InputSource(new StringReader(xml)));
        }
        catch (SAXException | IOException e)
        {
            throw new RuntimeException("Failed to parse payload XML",e);
        }
    }

    public static <T> T directChild(Node node, String childTagName, Function<String,T> mapper) {
        return mapper.apply( directChild(node,childTagName).getTextContent() );
    }

    public static Optional<Node> optDirectChild(Node node,String childTagName)
    {
        return asStream(node.getChildNodes())
            .filter( x -> x.getNodeType() == Node.ELEMENT_NODE && x.getNodeName().equals( childTagName) )
            .findFirst();
    }

    public static Stream<Node> directChildren(Node node,String childTagName)
    {
        return asStream(node.getChildNodes()).filter( x -> x.getNodeType() == Node.ELEMENT_NODE && x.getNodeName().equals( childTagName) );
    }

    public static Node directChild(Node node,String childTagName)
    {
        return optDirectChild(node, childTagName)
            .orElseThrow( () -> new NoSuchElementException("<"+node.getNodeName()+"/> tag has no direct <"+childTagName+"/> child node"));
    }

    public static String toString(Node document)
    {
        try {
            final Transformer transformer = TransformerFactory.newDefaultInstance().newTransformer();
            final StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(document), new StreamResult(writer));
            return writer.getBuffer().toString();
        }
        catch (Exception e)
        {
            throw new RuntimeException("Failed to convert Document to String",e);
        }
    }

    public static DocumentBuilder createDocumentBuilder()
    {
        final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try
        {
            return factory.newDocumentBuilder();
        }
        catch (ParserConfigurationException e)
        {
            throw new RuntimeException("Failed to parse payload XML",e);
        }
    }

    public static XPathExpression xpath(String expression) {
        try
        {
            final XPathFactory factory = XPathFactory.newDefaultInstance();
            return factory.newXPath().compile(expression);
        }
        catch (XPathExpressionException e)
        {
            throw new RuntimeException("Faile to compile '" + expression + "'", e);
        }
    }

    public static Stream<Node> asStream(NodeList list) {
        final Iterator<Node> it = asIterator(list);
        return StreamSupport.stream(Spliterators.spliteratorUnknownSize(it, Spliterator.ORDERED), false);
    }

    public static Iterable<Node> evalIterable(XPathExpression expr, Node node)
    {
        return asIterable(eval(expr, node));
    }

    public static Iterable<Node> asIterable(NodeList list) {
        return () -> asIterator(list);
    }

    public static Stream<Node> evalNodeStream(XPathExpression expr, Node node) {
        return asStream( eval(expr,node) );
    }

    public static Iterator<Node> evalNodeIterator(XPathExpression expr, Node node) {
        return asIterator( eval(expr,node) );
    }

    public static String evalString(XPathExpression expr, Node node) {
        try
        {
            return (String) expr.evaluate(node,XPathConstants.STRING);
        }
        catch (XPathExpressionException e)
        {
            throw new RuntimeException("Failed to apply XPATH expression", e);
        }
    }

    public static Optional<Node> unique(NodeList list) {
        if ( list.getLength() == 0 ) {
            return Optional.empty();
        }
        if ( list.getLength() > 1 ) {
            throw new IllegalStateException("Found more than one matching entry for a given UUID ?");
        }
        return Optional.of(list.item(0));
    }

    public static Optional<Node> evalUnique(XPathExpression expr, Node node)
    {
        final Stream<Node> nodeStream = asStream( eval( expr, node ) );
        final List<Node> list = nodeStream.collect( Collectors.toList() );
        return switch( list.size() ) {
            case 0 -> Optional.empty();
            case 1 -> Optional.of( list.get(0) );
            default -> throw new IllegalStateException( "Found multiple matching XML nodes, expected at most one" );
        };
    }

    public static NodeList eval(XPathExpression expr, Node node) {
        try
        {
            return (NodeList) expr.evaluate(node, XPathConstants.NODESET);
        }
        catch (XPathExpressionException e)
        {
            throw new RuntimeException("Failed to apply XPATH expression", e);
        }
    }

    public static Iterator<Node> asIterator(NodeList list) {
        return new Iterator<>()
        {
            private int idx = 0;
            private final int len = list.getLength();

            @Override
            public boolean hasNext()
            {
                return idx < len;
            }

            @Override
            public Node next()
            {
                if (!hasNext())
                {
                    throw new NoSuchElementException("Already at end of iteration");
                }
                return list.item(idx++);
            }
        };
    }
}