/*
 * Copyright (c) 2009, 2024, Oracle and/or its affiliates. All rights reserved.
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

package com.sun.security.jgss;

import sun.security.util.SecurityProperties;

import java.util.function.Predicate;
import java.util.stream.Stream;

/**
 * Kerberos 5 AuthorizationData entry.
 *
 * @since 1.7
 */
public final class AuthorizationDataEntry {

    private final int type;
    private final byte[] data;

    /**
     * Create an AuthorizationDataEntry object.
     * @param type the ad-type
     * @param data the ad-data, a copy of the data will be saved
     * inside the object.
     */
    public AuthorizationDataEntry(int type, byte[] data) {
        this.type = type;
        this.data = data.clone();
    }

    /**
     * Get the ad-type field.
     * @return ad-type
     */
    public int getType() {
        return type;
    }

    /**
     * Get a copy of the ad-data field.
     * @return ad-data
     */
    public byte[] getData() {
        return data.clone();
    }

    public String toString() {
        return "AuthorizationDataEntry: type="+type+", data=" +
                data.length + " bytes:\n" +
                new sun.security.util.HexDumpEncoder().encodeBuffer(data);
    }

    static int[] interestedTypes;

    static {
        String prop = SecurityProperties.privilegedGetOverridable(
                "jdk.security.krb5.default.interested.ad-type");
        if (prop == null) {
            interestedTypes = new int[0];
        } else {
            interestedTypes = Stream.of(prop.split("\\s*,\\s*"))
                    .filter(Predicate.not(String::isEmpty))
                    .mapToInt(Integer::parseInt)
                    .toArray();
        }
    }

    /**
     * Sets the interested ad-type values.
     * <p>
     * When {@code ExtendedGSSContext.inquireSecContext(InquireType.KRB5_GET_AUTHZ_DATA)}
     * is called, only entries whose ad-type in this list are guaranteed to
     * be retrieved. The default values are {@code {1, 4, 5, 8, 96, 97, 128, 129, 143}}.
     *
     * @param types interested ad-type values
     * @return the old interested ad-type values
     * @throws IllegalArgumentException if {@code types} is null
     */
    public static int[] setInterestedTypes(int[] types) {
        if (types == null) {
            throw new IllegalArgumentException("Interested types cannot be null or empty");
        }
        int[] old = interestedTypes;
        interestedTypes = types.clone();
        return old;
    }
}
