/*
 * Copyright (c) 2024, Oracle and/or its affiliates. All rights reserved.
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

package sun.security.jgss;

import sun.security.jgss.krb5.Krb5Util;
import sun.security.util.HexDumpEncoder;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.security.Key;

/**
 * The session key returned by inquireSecContext(KRB5_INQ_SSPI_SESSION_KEY)
 */
public class KerberosSessionKey implements Key {
    private static final long serialVersionUID = 699307378954123869L;

    @SuppressWarnings("serial") // Not statically typed as Serializable
    private final int etype;
    private final byte[] keyBytes;

    public KerberosSessionKey(int etype, byte[] keyBytes) {
        this.etype = etype;
        this.keyBytes = keyBytes.clone();
    }

    @Override
    public String getAlgorithm() {
        return Integer.toString(etype);
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return keyBytes.clone();
    }

    @Override
    public String toString() {
        return "Kerberos session key: etype=" + etype
                + ", " + Krb5Util.keyInfo(keyBytes);
    }

    /**
     * Restores the state of this object from the stream.
     *
     * @param  stream the {@code ObjectInputStream} from which data is read
     * @throws IOException if an I/O error occurs
     * @throws ClassNotFoundException if a serialized class cannot be loaded
     */
    @java.io.Serial
    private void readObject(ObjectInputStream stream)
            throws IOException, ClassNotFoundException {
        throw new InvalidObjectException
                ("KerberosSessionKey not directly deserializable");
    }
}
