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

import de.codesourcery.keepass.core.util.Logger;
import de.codesourcery.keepass.core.util.LoggerFactory;
import de.codesourcery.keepass.core.util.Serializer;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.zip.GZIPInputStream;

/**
 * Inner file header, introduced with KDBX 4.0 format
 *
 * See https://keepass.info/help/kb/kdbx_4.html#innerhdr
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class InnerHeader
{
    private static Logger LOG = LoggerFactory.getLogger(Database.class );

    /*
KDBX 4 files have an inner, binary header.
This header precedes the XML part; especially, it is compressed
(if the compression option is turned on) and encrypted (which is the reason why we call it the inner header).
Directly after the inner header, the XML part follows (in the same compression and encryption stream).

The inner header can store entry attachments, which is the primary motivation for the introduction of the inner header. Up to KDBX 3.1, entry attachments were encoded using Base64 and stored in the XML part. Compared to this, the KDBX 4 inner header approach results in a reduced database file size and improved loading/saving performance.
For Developers
The structure of the inner header is similar to the one of the outer header. It consists of arbitrarily many items of the following form:

    [1 byte] Item type.
    [4 bytes] Data length n (Int32, little-endian).
    [n bytes] Data D.

The following item types are supported:

    0x00: End of header.
    0x01: Inner random stream ID (this supersedes the inner random stream ID stored in the outer header of a KDBX 3.1 file).
    0x02: Inner random stream key (this supersedes the inner random stream key stored in the outer header of a KDBX 3.1 file).
    0x03: Binary (entry attachment). D = F ‖ M, where F is one byte and M is the binary content (i.e. the actual entry attachment data). F stores flags for the binary; supported flags are:
        0x01: The user has turned on process memory protection for this binary.

The inner header must end with an item of type 0x00 (and n = 0).
     */

    public final List<TLV<TLV.InnerHeaderType>> entries = new ArrayList<>();

    public TLV<TLV.InnerHeaderType> get(TLV.InnerHeaderType type) {
        return getHeader( type ).orElseThrow( () -> new RuntimeException( "Failed to find inner header " + type) );
    }

    public Optional<TLV<TLV.InnerHeaderType>> getHeader(TLV.InnerHeaderType type) {
        final List<TLV<TLV.InnerHeaderType>> matches = entries.stream().filter( x -> x.hasType( type ) ).collect( Collectors.toList() );
        return switch( matches.size() )
            {
                case 0 -> Optional.empty();
                case 1 -> Optional.of( matches.get( 0 ) );
                default -> throw new IllegalStateException( "Expected at most 1 inner file header of type " + type + " but found " + matches.size() );
            };
    }

    public Optional<byte[]> getHeaderDataDecompressed(TLV.InnerHeaderType type)
    {
        return getHeader( type ).map( x ->
        {
            try
            {
                return decompress( x.rawValue );
            }
            catch( IOException e )
            {
                throw new RuntimeException( "Failed to GZIP de-compress inner header " + type, e );
            }
        });
    }

    public void read(Serializer buffer) throws IOException
    {
        // read header entries
        this.entries.clear();
        while ( true ) {
            final TLV<TLV.InnerHeaderType> tlv = TLV.readV4( buffer, TLV.InnerHeaderType::lookup, TLV.InnerHeaderType.class );
            LOG.debug( "Got inner header: " + tlv );
            this.entries.add(tlv);
            if ( tlv.hasType( TLV.InnerHeaderType.END_OF_HEADER ) ) {
                break;
            }
        }
    }

    private static byte[] decompress(byte[] input) throws IOException
    {
        try ( final GZIPInputStream gzipIn = new GZIPInputStream(new ByteArrayInputStream(input) ) )
        {
            return gzipIn.readAllBytes();
        }
    }
}
