/*
 * Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
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

import jdk.test.lib.Asserts;

import javax.crypto.KEM;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.AlgorithmParameterSpec;

/*
 * @test
 * @bug 8888888
 * @library /test/lib
 * @summary Ensure destroyed keys cannot be used anymore
 */
public class Destroyed {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "SunJCE");
        PrivateKey sk1 = kpg.generateKeyPair().getPrivate();

        // Normal case
        KEM.getInstance("ML-KEM", "SunJCE").newDecapsulator(sk1);

        // newDecapsulator() with a destroyed key
        sk1.destroy();
        Asserts.assertThrows(IllegalStateException.class,
                () -> KEM.getInstance("ML-KEM", "SunJCE").newDecapsulator(sk1));

        KeyPair kp = kpg.generateKeyPair();
        KEM.Encapsulated enc = KEM.getInstance("ML-KEM", "SunJCE")
                .newEncapsulator(kp.getPublic()).encapsulate();

        // A foreign private key
        var sk2 = new MyPrivateKey(
                kp.getPrivate().getAlgorithm(),
                kp.getPrivate().getFormat(),
                kp.getPrivate().getEncoded(),
                kp.getPrivate().getParams(),
                new boolean[1]);
        KEM.Decapsulator d1 = KEM.getInstance("ML-KEM", "SunJCE")
                .newDecapsulator(sk2);
        sk2.destroy();

        // A new internal key is created, so destroying after
        // newDecapsulator() has no effect.
        d1.decapsulate(enc.encapsulation());
        // That said, it still cannot be used in newDecapsulator().
        Asserts.assertThrows(IllegalStateException.class,
                () -> KEM.getInstance("ML-KEM", "SunJCE").newDecapsulator(sk2));

        // A native private key
        PrivateKey sk3 = kp.getPrivate();
        KEM.Decapsulator d2 = KEM.getInstance("ML-KEM", "SunJCE")
                .newDecapsulator(sk3);
        d2.decapsulate(enc.encapsulation());
        sk3.destroy();
        // Even after newDecapsulator(), destroying a native private key
        // prevent decapsulate() from being called
        Asserts.assertThrows(IllegalStateException.class,
                () -> d2.decapsulate(enc.encapsulation()));
    }

    public record MyPrivateKey(
            String algorithm,
            String format,
            byte[] bytes,
            AlgorithmParameterSpec params,
            boolean[] destroyed) implements PrivateKey {
        public AlgorithmParameterSpec getParams() {
            return params;
        }
        public void destroy() {
            destroyed[0] = true;
        }
        public boolean isDestroyed() {
            return destroyed[0];
        }
        public String getAlgorithm() {
            return algorithm;
        }
        public String getFormat() {
            return format;
        }
        public byte[] getEncoded() {
            return bytes;
        }
    }
}
