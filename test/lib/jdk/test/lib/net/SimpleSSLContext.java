/*
 * Copyright (c) 2005, 2025, Oracle and/or its affiliates. All rights reserved.
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

package jdk.test.lib.net;

import java.util.*;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.function.Supplier;
import javax.net.ssl.*;

/**
 * Creates a simple usable SSLContext for SSLSocketFactory
 * or a HttpsServer using either a given keystore or a default
 * one in the test tree.
 */
public class SimpleSSLContext {

    SSLContext ssl;

    /**
     * loads default keystore from SimpleSSLContext
     * source directory
     */
    public SimpleSSLContext() throws IOException {
        this(() -> "TLS");
    }

    private SimpleSSLContext(Supplier<String> protocols) throws IOException {
        String proto = protocols.get();
        String paths = System.getProperty("test.src.path");
        StringTokenizer st = new StringTokenizer(paths, File.pathSeparator);
        while (st.hasMoreTokens()) {
            String path = st.nextToken();
            File f = new File(path, "jdk/test/lib/net/testkeys");
            if (f.exists()) {
                try (FileInputStream fis = new FileInputStream(f)) {
                    init(fis, proto);
                    break;
                }
            }
        }
    }

    /**
     * loads default keystore from given directory
     */
    public SimpleSSLContext(String dir) throws IOException {
        String file = dir + "/testkeys";
        try (FileInputStream fis = new FileInputStream(file)) {
            init(fis, "TLS");
        }
    }

    private void init(InputStream i, String protocol) throws IOException {
        try {
            char[] passphrase = "passphrase".toCharArray();
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(i, passphrase);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
            kmf.init(ks, passphrase);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
            tmf.init(ks);

            ssl = SSLContext.getInstance(protocol);
            ssl.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        } catch (KeyManagementException | KeyStoreException |
                UnrecoverableKeyException | CertificateException |
                NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    public static SSLContext getContext(String protocol) throws IOException {
        if(protocol == null || protocol.isEmpty()) {
            return new SimpleSSLContext().get();
        }
        else {
            return new SimpleSSLContext(() -> protocol).get();
        }
    }

    public SSLContext get() {
        return ssl;
    }
}
