/*
 * Copyright (c) 2021, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package sun.security.util;

import static sun.security.util.DerValue.*;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;

/**
 * A DerTree might be in 3 levels: full encoding, encoded content,
 * or subtree. At least one must be non-null and if there are multiple
 * non-nulls they must match. When editing on a node, always remember
 * to clean out content and encoding so that they can be recalculated.
 *
 * There are two ways to generate an indefinite length BER encoding:
 *
 * 1. Using the {@link #startIndefinite} methods in a try-with-resources
 * block. This allows starting an indefinite length encoding and you can
 * add other definite length (or more indefinite length) encodings inside
 * the block. When the block ends, an EOC will be added automatically.
 * The benefit is you can control the encoding at your will. The problem
 * is a lot of coding is needed. If the indefinite length encoding is
 * deep inside an ASN.1 definition, all levels of constructed value
 * around it must be indefinte and a try-with-resources block is needed.
 *
 * 2. Using the {@link #DerTree(byte, InputStream)} constructor along with
 * {@link #DerTree(byte, Supplier)}. This allows describing a DerTree
 * in its ASN.1 definition but it depends on the encoding method to read
 * from the stream and callback the supplier. It's important to make sure
 * contents are created (calculated) in their logic order. The current
 * implementation only supports the indefinite length encoding source
 * as an OCTET STRING.
 *
 * This class will accept byte array and subs without making a clone,
 * this means when the original data is modified the internal state of
 * this class will change as well. On the other hand, this class does not
 * leak any input data so it's not possible to modify the original data
 * or the internal states of this class by manipulating an instance of
 * this class, especially, toByteArray() does not return the internals.
*/
public class DerTree {

    private static final int BUFFER_SIZE = 1024;

    /**
     * Full encoding containing tag, length, and content, could be assigned in
     * {@link #wrap(byte[])}, or when encoding as an element of a SET where the
     * encoding must be pre-calculated for ordering and thus worth caching.
     */
    private byte[] encoding;

    /**
     * True if originally created as a SET. Note that the tag might be
     * modified after a {@link #asImplicitContext(int)} call.
     */
    private boolean isSet;

    private byte tag = -1;

    /**
     * Length of content and length of length bytes, they can be calculated
     * without generating the actual encoding. This makes it possible to
     * encode in stream mode.
     */
    private int len = -1, lenlen = -1;

    /**
     * Primitive or raw content. It is also filled in (partially)
     * when input is a source in {@link #DerTree(byte, InputStream)}.
     */
    private byte[] content;

    // supplier and source are only for OCTETSTRING at the moment.
    // They are meant for different uses: source is globally available
    // but could contain too many data and thus will lead to indefinite
    // length BER encoding. supplier might contain on-demand data that
    // is only available at encoding time, for example, calculated data
    // based on previous fields in the same tree.

    private Supplier<byte[]> supplier; // will only be read when getLens
    private InputStream source; // if long, will be indefinite length

    /**
     * Sub elements in a constructed value.
     */
    private DerTree[] subs;

    // Private constructors
    private DerTree(DerTree old) {
        this.encoding = old.encoding == null ? null : old.encoding.clone();
        this.isSet = old.isSet;
        this.tag = old.tag;
        this.len = old.len;
        this.lenlen = old.lenlen;
        this.content = old.content;
        this.supplier = old.supplier;
        this.source = old.source;
        this.subs = old.subs;
    }

    /**
     * Wrap an existing encoding.
     */
    private DerTree(byte[] encoding) {
        this.encoding = encoding;
    }

    /**
     * Creates a DerTree with raw content and tag
     */
    private DerTree(byte tag, byte[] content) {
        this.tag = tag;
        this.content = content;
    }

    /**
     * Creates a DerTree from an input stream. If there are too many
     * data in the stream, an indefinite BER encoding will be genrated.
     */
    private DerTree(byte tag, InputStream source) throws IOException {
        this.tag = tag;
        int available = source.available();
        if (available <= BUFFER_SIZE) {
            this.content = new byte[available];
            source.read(content);
        }
        if (source.available() > 0) {
            this.source = source;
        }
    }

    /**
     * Creates a DerTree with a future contnt supplier. The supplier
     * is only used when the data is needed in either encoding or length
     * calculation.
     */
    private DerTree(byte tag, Supplier<byte[]> supplier) {
        this.tag = tag;
        this.supplier = supplier;
    }

    /**
     * Creates a DerTree as a contructed value of sub-DerTree values.
     */
    private DerTree(byte tag, DerTree[] subs) {
        this.tag = tag;
        this.subs = subs;
    }

    // Output

    /**
     * Encode into the output stream. Note: this method does not
     * throw an IOException.
     */
    public DerTree encode(ByteArrayOutputStream os) {
        try {
            return encode((OutputStream) os);
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    /**
     * Encode into the output stream.
     */
    public DerTree encode(OutputStream os) throws IOException {
        return getLens().encode0(os);
    }

    /**
     * A handy method to get the encoding.
     */
    public byte[] toByteArray() {
        if (encoding == null) {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            encode(bout);
            return bout.toByteArray();
            // the output is not stored as encoding so it can be
            // returned without a clone. We don't expect this method
            // be called often. The encode(OutputStream) method is
            // always preferred.
        } else {
            return encoding.clone();
        }
    }

    /**
     * View the structure of this DerTree, only for debugging use.
     * @return
     */
    public String toString() {
        return toString0("", "");
    }

    // Private implementations

    private DerTree encode0(OutputStream os) throws IOException {
        if (encoding != null) {
            os.write(encoding);
        } else {
            if (len == Integer.MAX_VALUE) {
                os.write((tag | 0x20));
                os.write(0x80);
            } else {
                os.write(tag);
                writeLen(os, len);
            }
            if (source != null) {
                if (content != null) {
                    os.write(tag);
                    writeLen(os, content.length);
                    os.write(content);
                }
                byte[] buffer = new byte[BUFFER_SIZE];
                while (true) {
                    int n = source.read(buffer);
                    if (n <= 0) break;
                    os.write(tag);
                    writeLen(os, n);
                    os.write(buffer, 0, n);
                }
            } else if (content != null) {
                os.write(content);
            } else if (supplier != null) {
                os.write(supplier.get());
            } else {
                if (isSet && subs.length > 1) {
                    byte[][] sets = new byte[subs.length][];
                    for (int i = 0; i < subs.length; i++) {
                        if (subs[i].encoding == null) {
                            // Keep calling getLens() in case it's not calculated
                            ByteArrayOutputStream bout = new ByteArrayOutputStream(
                                    subs[i].getLens().len + subs[i].lenlen + 1);
                            subs[i].encode0(bout);
                            subs[i].encoding = bout.toByteArray();
                        }
                        sets[i] = subs[i].encoding;
                    }
                    Arrays.sort(sets, Arrays::compare);
                    for (int i = 0; i < sets.length; i++) {
                        os.write(sets[i]);
                    }
                } else {
                    for (DerTree t : subs) {
                        // Keep calling getLens() in case it's not calculated
                        t.getLens().encode0(os);
                    }
                }
            }
            if (len == Integer.MAX_VALUE) {
                os.write(0);
                os.write(0);
            }
        }
        return this;
    }

    // Calculating len and lenlen for encode()
    private DerTree getLens() {
        if (encoding != null || len >= 0) return this;
        if (source != null) {
            len = Integer.MAX_VALUE;
            return this;
        }
        if (supplier != null) {
            content = supplier.get();
            len = content.length;
        } else if (content != null) {
            len = content.length;
        } else {
            len = 0;
            boolean seeSource = false;
            for (var s : subs) {
                if (s.encoding != null) {
                    len += s.encoding.length;
                } else {
                    s.getLens();
                    if (s.len == Integer.MAX_VALUE) {
                        seeSource = true;
                        // Do not read on. Later fields might depend on
                        // this field (as a supplier) and we should not
                        // get the data prematurely. But this also means
                        // getLens is not complete and we should continue
                        // calling it inside encode0()
                        break;
                    } else {
                        len += s.len + s.lenlen + 1;
                    }
                }
            }
            if (seeSource) {
                len = Integer.MAX_VALUE;
            }
        }
        lenlen = len == Integer.MAX_VALUE ? -1 : len2lenlen(len);
        return this;
    }

    // Shows the structure, content or subs. Will not change internal states
    private String toString0(String here, String indent) {
        var sb = new StringBuilder();
        sb.append('[').append(here).append("]").append(indent);
        if (tag != -1) {
            sb.append(" : ").append(String.format("0x%02x", tag & 0xff));
        }
        if (encoding != null) {
            sb.append(" : ").append(encoding.length).append(" raw bytes");
        }
        if (content != null) {
            sb.append(" : ").append(content.length).append(" content bytes");
        }
        if (len >= 0) {
            sb.append(" : len = ").append(len);
        }
        if (lenlen >= 0) {
            sb.append(" : lenlen = ").append(lenlen);
        }
        sb.append('\n');
        if (subs != null) {
            int pos = 0;
            for (var sub : subs) {
                sb.append(sub.toString0(tag == tag_OctetString ? (here + 'c') : (here + pos), indent + "  "));
                pos++;
            }
        }
        return sb.toString();
    }

    private int len2lenlen(int len) {
        if (len < 128) {
            return 1;
        } else if (len < (1 << 8)) {
            return 2;
        } else if (len < (1 << 16)) {
            return 3;
        } else if (len < (1 << 24)) {
            return 4;
        } else {
            return 5;
        }
    }

    private void writeLen(OutputStream os, int len) throws IOException {
        if (len < 128) {
            os.write((byte)len);
        } else if (len < (1 << 8)) {
            os.write((byte)0x081);
            os.write((byte)len);
        } else if (len < (1 << 16)) {
            os.write((byte)0x082);
            os.write((byte)(len >> 8));
            os.write((byte)len);
        } else if (len < (1 << 24)) {
            os.write((byte)0x083);
            os.write((byte)(len >> 16));
            os.write((byte)(len >> 8));
            os.write((byte)len);
        } else {
            os.write((byte)0x084);
            os.write((byte)(len >> 24));
            os.write((byte)(len >> 16));
            os.write((byte)(len >> 8));
            os.write((byte)len);
        }
    }

    private static byte[] bytes(int i) {
        if (i < 0x80 && i >= 0xffffff80) {
            return new byte[] { (byte)i };
        } else if (i < 0x8000 && i >= 0xffff8000) {
            return new byte[] { (byte)(i >>> 8), (byte)i };
        } else if (i < 0x800000 && i >= 0xff800000) {
            return new byte[] { (byte)(i >>> 16), (byte)(i >>> 8), (byte)i };
        } else {
            return new byte[] { (byte)(i >>> 24), (byte)(i >>> 16), (byte)(i >>> 8), (byte)i };
        }
    }

    // indefinite helper

    /**
     * Starts an indefinite length BER encoding with the specified tag.
     */
    public static IndefiniteHolder startIndefinite(OutputStream os, byte tag)
            throws IOException {
        return new IndefiniteHolder(os, tag);
    }

    /**
     * Starts an indefinite length BER encoding using the same tag as the
     * specified DerTree. For example:
     *
     * <pre>{@code
     * try (var v = startIndefinite(os, OCTETSTRING(new byte[0]))) {
     *     OCTETSTRING(new byte[1]).encode(os);
     *     OCTETSTRING(new byte[1]).encode(os);
     *     OCTETSTRING(new byte[1]).encode(os);
     * }
     * }</pre>>
     */
    public static IndefiniteHolder startIndefinite(
            OutputStream os, DerTree tagSupplier) throws IOException {
        return new IndefiniteHolder(os, (byte)(tagSupplier.tag | 0x20));
    }

    // This class must be made public even if you never use its name
    public static class IndefiniteHolder implements Closeable {
        private final OutputStream os;
        public IndefiniteHolder(OutputStream os, byte tag) throws IOException {
            this.os = os;
            os.write((int)tag);
            os.write(0x80);
        }
        @Override
        public void close() throws IOException {
            os.write(new byte[2]);
        }
    }

    private static DerTree makeString(byte type, Charset t, String s) {
        return new DerTree(type, s.getBytes(t));
    }

    /**
     * Implicitly wrap this DerTree into a new context-specific DerTree
     * with the specified tag number.
     */
    public DerTree asImplicitContext(int i) {
        DerTree n = new DerTree(this);
        n.tag = (byte) (TAG_CONTEXT + 0x20 + i);
        if (n.encoding != null) {
            n.encoding[0] = n.tag;
        }
        return n;
    }

    // public creators

    static Instant I2050 = ZonedDateTime.of(2050, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC).toInstant();
    static Instant I1950 = ZonedDateTime.of(1950, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC).toInstant();
    static DateTimeFormatter UTC_FORMAT = DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
    static DateTimeFormatter GENERAL_FORMAT = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
    public static DerTree TIME(Instant t) {
        if (t.isBefore(I1950) || !t.isBefore(I2050)) {
            return new DerTree(tag_GeneralizedTime,
                    GENERAL_FORMAT.format(t).getBytes(StandardCharsets.ISO_8859_1));
        } else {
            return new DerTree(tag_UtcTime,
                    UTC_FORMAT.format(t).getBytes(StandardCharsets.ISO_8859_1));
        }
    }

    public static DerTree INTEGER(int i) {
        return new DerTree(tag_Integer, bytes(i));
    }
    public static DerTree INTEGER(String i) {
        return INTEGER(new BigInteger(i));
    }
    public static DerTree INTEGER(BigInteger i) {
        return new DerTree(tag_Integer, i.toByteArray());
    }
    public static DerTree NULL() {
        return new DerTree(tag_Null, new byte[0]);
    }
    public static DerTree ENUMERATED(int i) {
        return new DerTree(tag_Enumerated, bytes(i));
    }
    public static DerTree BOOLEAN(boolean b) {
        return new DerTree(tag_Boolean, new byte[b ? 0xff : 0]);
    }

    public static DerTree OID(KnownOIDs oid) {
        return OID(ObjectIdentifier.of(oid));
    }
    public static DerTree OID(ObjectIdentifier oid) {
        return new DerTree(tag_ObjectId, oid.encoding());
    }

    public static DerTree BITSTRING(byte[] bits) {
        byte[] content = new byte[bits.length + 1];
        content[0] = 0;
        System.arraycopy(bits, 0, content, 1, bits.length);
        return new DerTree(tag_BitString, content);
    }

    public static DerTree OCTETSTRING(byte[] data) {
        return new DerTree(tag_OctetString, data);
    }
    public static DerTree OCTETSTRING(InputStream source) throws IOException {
        return new DerTree(tag_OctetString, source);
    }
    public static DerTree OCTETSTRING(Supplier<byte[]> supplier) {
        return new DerTree(tag_OctetString, supplier);
    }

    public static DerTree UTF8STRING(String s) {
        return makeString(tag_UTF8String, StandardCharsets.UTF_8, s);
    }
    public static DerTree PRINTABLESTRING(String s) {
        return makeString(tag_PrintableString, StandardCharsets.US_ASCII, s);
    }
    public static DerTree T61STRING(String s) {
        return makeString(tag_T61String, StandardCharsets.ISO_8859_1, s);
    }
    public static DerTree IA5STRING(String s) {
        return makeString(tag_IA5String, StandardCharsets.US_ASCII, s);
    }
    public static DerTree GENERALSTRING(String s) {
        return makeString(tag_GeneralString, StandardCharsets.US_ASCII, s);
    }
    public static DerTree UNIVERSALSTRING(String s) {
        return makeString(tag_UniversalString, Charset.forName("UTF_32BE"), s);
    }
    public static DerTree BMPSTRING(String s) {
        return makeString(tag_BMPString, StandardCharsets.UTF_16BE, s);
    }

    // Put content of a DerTree as an OCTET STRING
    public static DerTree OCTETSTRING(DerTree node) {
        return new DerTree(tag_OctetString, new DerTree[]{node});
    }

    public static DerTree SEQUENCE(DerTree... nodes) {
        return new DerTree(tag_Sequence, nodes);
    }
    public static DerTree SET(DerTree... nodes) {
        var n = new DerTree(tag_Set, nodes);
        n.isSet = true;
        return n;
    }

    public static DerTree CONTEXT(int i, DerTree... nodes) {
        return new DerTree((byte)(TAG_CONTEXT + 0x20 + i), nodes);
    }
    public static DerTree APPLICATION(int i, DerTree... nodes) {
        return new DerTree((byte)(TAG_APPLICATION + 0x20 + i), nodes);
    }

    public static DerTree wrap(byte[] data) throws IOException {
        return new DerTree(data);
    }
}
