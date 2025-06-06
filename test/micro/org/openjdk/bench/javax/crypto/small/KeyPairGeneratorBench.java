/*
 * Copyright (c) 2015, 2025, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
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
package org.openjdk.bench.javax.crypto.small;

import org.openjdk.jmh.annotations.Param;

public class KeyPairGeneratorBench extends org.openjdk.bench.javax.crypto.full.KeyPairGeneratorBench {

    @Param({"DSA", "RSA"})
    private String algorithm;

    @Param({"2048"})
    private int keyLength;

    public static class MLDSA extends KeyPairGeneratorBench {

        @Param({"ML-DSA-65"})
        private String algorithm;

        @Param({"0"}) // ML_DSA key length is not supported
        private int keyLength;
    }

    public static class MLKEM extends KeyPairGeneratorBench {

        @Param({"ML-KEM-768"})
        private String algorithm;

        @Param({"0"}) // ML-KEM key length is not supported
        private int keyLength;
    }

}
