/*
 * Copyright (c) 2021, Oracle and/or its affiliates. All rights reserved.
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

/*
 * @test
 * @modules java.base/sun.security.util
 *          java.base/sun.security.pkcs
 *          java.base/sun.security.x509
 */
import sun.security.pkcs.PKCS7;
import sun.security.util.KnownOIDs;
import sun.security.x509.KeyIdentifier;

import static sun.security.util.DerTree.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;

public class DerTreeTest {

    record CertAndKey(Certificate cert, PrivateKey key) {}

    public static void main(String[] args) throws Exception {
        testAllInts();      // ensures correctly encoding of ints
        var ck = gencert(); // example to generated a certificate
        setof();            // ensure ordering in a SET OF
        ber();              // check startIndefiniteLength
        p7(ck);             // PKCS7 DER encoding
        p7indef(ck);        // PKCS7 indefinite length DER with startIndefiniteLength
        p7source(ck);       // PKCS7 indefinite length DER with source and supplier
        as();               // check asImplicitContext
    }

    static void as() throws IOException {
        var t = SEQUENCE(PRINTABLESTRING("x"));
        t = wrap(t.toByteArray());
        var u = SET(t.asImplicitContext(1),
                t.asImplicitContext(0),
                t.asImplicitContext(2));
        if (!HexFormat.of().formatHex(u.toByteArray())
                .equals("310fa003130178a103130178a203130178")) {
            throw new RuntimeException();
        }
    }

    static void testAllInts() {
        for (int i = 0xff800000 - 10; i < 0x800000 + 10; i++) {
            var b1 = INTEGER(i).toByteArray();
            var b2 = INTEGER(BigInteger.valueOf(i)).toByteArray();
            if (!Arrays.equals(b1, b2)) {
                System.out.println(HexFormat.ofDelimiter(":").formatHex(b1));
                System.out.println(HexFormat.ofDelimiter(":").formatHex(b2));
                throw new RuntimeException(String.format("%d %x", i, i));
            }
        }
    }

    static CertAndKey gencert() throws Exception {
        var kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        var kp = kpg.generateKeyPair();
        var pub = kp.getPublic();
        var pri = kp.getPrivate();
        var skid = new KeyIdentifier(pub).getIdentifier();
        var ti = SEQUENCE(CONTEXT(0, INTEGER(2)),
                INTEGER("2125386050206088370"),
                SEQUENCE(OID(KnownOIDs.SHA256withECDSA)),
                SEQUENCE(SET(SEQUENCE(OID(KnownOIDs.CommonName), PRINTABLESTRING("a")))),
                SEQUENCE(TIME(Instant.parse("2021-12-26T02:11:34Z")), TIME(Instant.parse("2024-09-21T02:11:34Z"))),
                SEQUENCE(SET(SEQUENCE(OID(KnownOIDs.CommonName), PRINTABLESTRING("a")))),
                wrap(pub.getEncoded()),
                CONTEXT(3, SEQUENCE(SEQUENCE(OID(KnownOIDs.SubjectKeyID), OCTETSTRING(skid)))));
        var c = SEQUENCE(
                ti,
                SEQUENCE(OID(KnownOIDs.SHA256withECDSA)),
                BITSTRING(sign(pri, ti.toByteArray())));
        var cf = CertificateFactory.getInstance("X.509");
        var crt = cf.generateCertificate(new ByteArrayInputStream(c.toByteArray()));
        crt.verify(crt.getPublicKey());
        crt.verify(pub);
        return new CertAndKey(crt, pri);
    }

    static void setof() {
        var t1 = SET(UTF8STRING("123"), UTF8STRING("124"), UTF8STRING("122"));
        if (!HexFormat.of().formatHex(t1.toByteArray())
                .equals("310f0c033132320c033132330c03313234")) {
            throw new RuntimeException();
        }
    }

    static void ber() throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        try (Closeable v2 = startIndefinite(os, OCTETSTRING(new byte[0]))) {
            OCTETSTRING(new byte[1]).encode(os);
            OCTETSTRING(new byte[1]).encode(os);
            OCTETSTRING(new byte[1]).encode(os);
        }
        if (!HexFormat.of().formatHex(os.toByteArray())
                .equals("24800401000401000401000000")) {
            throw new RuntimeException();
        }
    }

    static void p7indef(CertAndKey ck) throws Exception {
        var key = ck.key();
        var bout = new ByteArrayOutputStream();
        try (var v6 = startIndefinite(bout, SEQUENCE())) {
            OID(KnownOIDs.SignedData).encode(bout);
            var md = MessageDigest.getInstance("SHA-256");
            try (var v5 = startIndefinite(bout, CONTEXT(0))) {
                try (var v4 = startIndefinite(bout, SEQUENCE())) {
                    INTEGER(1).encode(bout);
                    SET(SEQUENCE(OID(KnownOIDs.SHA_256), NULL())).encode(bout);
                    try (var v3 = startIndefinite(bout, SEQUENCE())) {
                        OID(KnownOIDs.Data).encode(bout);
                        try (var v2 = startIndefinite(bout, CONTEXT(0))) {
                            try (var v1 = startIndefinite(bout, OCTETSTRING(new byte[0]))) {
                                try (InputStream is = new ByteArrayInputStream(data())) {
                                    byte[] buffer = new byte[100];
                                    while (true) {
                                        int n = is.read(buffer);
                                        if (n >= 0) {
                                            md.update(buffer, 0, n);
                                            OCTETSTRING(Arrays.copyOf(buffer, n)).encode(bout);
                                        } else {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    CONTEXT(0, wrap(ck.cert().getEncoded())).encode(bout);
                    var attrs = SET(
                            SEQUENCE(OID(KnownOIDs.CMSAlgorithmProtection),
                                    SET(SEQUENCE(SEQUENCE(OID(KnownOIDs.SHA_256), NULL()), CONTEXT(1, OID(KnownOIDs.SHA256withECDSA))))),
                            SEQUENCE(OID(KnownOIDs.SigningTime), SET(TIME(Instant.parse("2021-12-30T20:02:01Z")))),
                            SEQUENCE(OID(KnownOIDs.ContentType), SET(OID(KnownOIDs.Data))),
                            SEQUENCE(OID(KnownOIDs.MessageDigest), SET(OCTETSTRING(md.digest()))));
                    SET(SEQUENCE(
                            INTEGER(1),
                            SEQUENCE(SEQUENCE(SET(SEQUENCE(OID(KnownOIDs.CommonName), PRINTABLESTRING("a")))), INTEGER("2125386050206088370")),
                            SEQUENCE(OID(KnownOIDs.SHA_256), NULL()),
                            attrs.asImplicitContext(0),
                            SEQUENCE(OID(KnownOIDs.SHA256withECDSA)),
                            OCTETSTRING(sign(key, attrs.toByteArray())))).encode(bout);
                }
            }
        }
        var pkcs7 = new PKCS7(bout.toByteArray());
        if (pkcs7.verify() == null) {
            throw new RuntimeException();
        }
    }

    static void p7(CertAndKey ck) throws Exception {
        var cert = CONTEXT(0, wrap(ck.cert().getEncoded()));
        var key = ck.key();
        byte[] sf = data();
        var data = SEQUENCE(OID(KnownOIDs.Data), CONTEXT(0, OCTETSTRING(sf)));
        var digest = MessageDigest.getInstance("SHA-256").digest(sf);
        var attrs = SET(
                SEQUENCE(OID(KnownOIDs.CMSAlgorithmProtection),
                        SET(SEQUENCE(SEQUENCE(OID(KnownOIDs.SHA_256), NULL()), CONTEXT(1, OID(KnownOIDs.SHA256withECDSA))))),
                SEQUENCE(OID(KnownOIDs.SigningTime), SET(TIME(Instant.parse("2021-12-30T20:02:01Z")))),
                SEQUENCE(OID(KnownOIDs.ContentType), SET(OID(KnownOIDs.Data))),
                SEQUENCE(OID(KnownOIDs.MessageDigest), SET(OCTETSTRING(digest))));
        var p7 = SEQUENCE(OID(KnownOIDs.SignedData),
                CONTEXT(0, SEQUENCE(INTEGER(1),
                        SET(SEQUENCE(OID(KnownOIDs.SHA_256), NULL())),
                        data,
                        cert,
                        SET(SEQUENCE(
                                INTEGER(1),
                                SEQUENCE(SEQUENCE(SET(SEQUENCE(OID(KnownOIDs.CommonName), PRINTABLESTRING("a")))), INTEGER("2125386050206088370")),
                                SEQUENCE(OID(KnownOIDs.SHA_256), NULL()),
                                attrs.asImplicitContext(0),
                                SEQUENCE(OID(KnownOIDs.SHA256withECDSA)),
                                OCTETSTRING(sign(key, attrs.toByteArray())))))));
        var pkcs7 = new PKCS7(p7.toByteArray());
        if (pkcs7.verify() == null) {
            throw new RuntimeException();
        }
    }

    private static byte[] sign(PrivateKey k, byte[] input) {
        try {
            var s = Signature.getInstance("SHA256withECDSA");
            s.initSign(k);
            s.update(input);
            return s.sign();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static void p7source(CertAndKey ck) throws Exception {
        var cert = CONTEXT(0, wrap(ck.cert().getEncoded()));
        var key = ck.key();
        var is = new DigestInputStream(new ByteArrayInputStream(data()), MessageDigest.getInstance("SHA-256"));
        var data = SEQUENCE(OID(KnownOIDs.Data), CONTEXT(0, OCTETSTRING(is)));
        var attrs = SET(
                SEQUENCE(OID(KnownOIDs.CMSAlgorithmProtection),
                        SET(SEQUENCE(SEQUENCE(OID(KnownOIDs.SHA_256), NULL()), CONTEXT(1, OID(KnownOIDs.SHA256withECDSA))))),
                SEQUENCE(OID(KnownOIDs.SigningTime), SET(TIME(Instant.parse("2021-12-30T20:02:01Z")))),
                SEQUENCE(OID(KnownOIDs.ContentType), SET(OID(KnownOIDs.Data))),
                SEQUENCE(OID(KnownOIDs.MessageDigest), SET(OCTETSTRING(() -> is.getMessageDigest().digest()))));
        var p7 = SEQUENCE(OID(KnownOIDs.SignedData),
                CONTEXT(0, SEQUENCE(INTEGER(1),
                        SET(SEQUENCE(OID(KnownOIDs.SHA_256), NULL())),
                        data,
                        cert,
                        SET(SEQUENCE(
                                INTEGER(1),
                                SEQUENCE(SEQUENCE(SET(SEQUENCE(OID(KnownOIDs.CommonName), PRINTABLESTRING("a")))), INTEGER("2125386050206088370")),
                                SEQUENCE(OID(KnownOIDs.SHA_256), NULL()),
                                attrs.asImplicitContext(0),
                                SEQUENCE(OID(KnownOIDs.SHA256withECDSA)),
                                OCTETSTRING(() -> sign(key, attrs.toByteArray())))))));
        var bout = new ByteArrayOutputStream();
        p7.encode(bout);
        var dump = bout.toByteArray();
        var pkcs7 = new PKCS7(dump);
        if (pkcs7.verify() == null) {
            throw new RuntimeException();
        }
    }

    private static byte[] data() {
        return new byte[2048];
    }
}
