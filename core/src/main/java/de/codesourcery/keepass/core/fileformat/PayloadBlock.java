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

import de.codesourcery.keepass.core.crypto.Hash;
import de.codesourcery.keepass.core.util.Logger;
import de.codesourcery.keepass.core.util.LoggerFactory;
import de.codesourcery.keepass.core.util.Misc;
import de.codesourcery.keepass.core.util.Serializer;
import org.apache.commons.lang3.Validate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Payload block from inside the KeePassX file.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class PayloadBlock
{
    private static final Logger LOG = LoggerFactory.getLogger( PayloadBlock.class );

    public static final int BLOCK_ID_PAYLOAD = 0x00;
    public static final int BLOCK_ID_END_OF_PAYLOAD = 0x01;

    public final int blockId;
    public byte[] blockHash;
    public byte[] blockData;
    public final boolean gzipCompressed;

    public PayloadBlock(int blockId, byte[] blockHash, byte[] blockData,boolean gzipCompressed)
    {
        Validate.notNull(blockHash, "blockHash must not be null");
        Validate.notNull(blockData, "blockData must not be null");
        this.blockId = blockId;
        this.blockHash = blockHash;
        this.blockData = blockData;
        this.gzipCompressed = gzipCompressed;
    }

    public void setData(byte[] data)
    {
        this.blockData = gzipCompressed ? compressData(data) : data;
        this.blockHash = Hash.sha256(this.blockData);
    }

    private byte[] compressData(byte[] data)
    {
        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (GZIPOutputStream out = new GZIPOutputStream(bos ) ) {
            out.write(data);
        }
        catch (IOException e)
        {
            throw new RuntimeException("GZIP compression failed?",e);
        }
        return bos.toByteArray();
    }

    public boolean checksumOk()
    {
        if ( this.blockId == 0x01 && blockData.length == 0 && Arrays.equals( new byte[32], blockHash ) ) {
            return true;
        }
        final byte[] actualHash = Hash.sha256(blockData);
        return Arrays.equals( blockHash, actualHash );
    }

    public byte[] getDecompressedPayload() {
        if ( ! gzipCompressed ) {
            return blockData;
        }
        try ( final GZIPInputStream gzipIn = new GZIPInputStream(new ByteArrayInputStream(blockData) ) )
        {
            return gzipIn.readAllBytes();
        }
        catch (IOException e)
        {
            throw new RuntimeException("GZIP decompression failed",e);
        }
    }

    public static PayloadBlock read(boolean isCompressedPayload, Serializer helper) throws IOException {
        final int blockId = helper.readInt("payload block ID");
        final byte[] blockHash = helper.readBytes(32, "payload block hash");
        final int blockSize = helper.readInt("payload block size");
        final byte[] blockData = blockSize > 0 ? helper.readBytes(blockSize, "payload block data") : new byte[0];

        LOG.trace("Got payload block of type 0x" + Integer.toHexString(blockId) + ", length=" + blockSize
                               + ", hash=" + Misc.toHexString(blockHash));
        final PayloadBlock result = new PayloadBlock(blockId, blockHash, blockData, isCompressedPayload);
        if ( ! result.checksumOk() ) {
            throw new RuntimeException("Checksum failure on block "+result);
        }
        return result;
    }

    public void write(Serializer helper) throws IOException
    {
        if ( ! checksumOk() ) {
            throw new IllegalStateException("Refusing to write block with bad checksum: "+this);
        }
        helper.writeInt(this.blockId);
        helper.writeBytes(this.blockHash);
        helper.writeInt(this.blockData.length);
        if ( this.blockData.length > 0 ) {
            helper.writeBytes(this.blockData);
        }
    }

    @Override
    public String toString()
    {
        return "PayloadBlock{" +
                   "blockId=" + blockId +
                   ", blockHash=" + Misc.toHexString(blockHash) +
                   ", blockSize=" + blockData.length +
                   ", gzipCompressed=" + gzipCompressed +
                   '}';
    }
}
