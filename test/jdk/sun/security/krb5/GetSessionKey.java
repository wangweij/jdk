/*
 * Copyright (c) 2024, Oracle and/or its affiliates. All rights reserved.
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

import com.sun.security.auth.module.Krb5LoginModule;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import sun.security.krb5.internal.APReq;
import sun.security.krb5.internal.crypto.KeyUsage;
import sun.security.util.DerValue;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.EncryptionKey;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.LoginException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;

public class GetSessionKey {

    static Boolean isNative = Boolean.getBoolean("sun.security.jgss.native");
    static Oid krb5;
    static String peer = null;

    private static Subject krb5login() throws LoginException {
        Subject subject = new Subject();
        if (isNative) {
            return subject;
        }
        Krb5LoginModule krb5 = new Krb5LoginModule();
        krb5.initialize(subject, null, Map.of(), Map.of(
                "doNotPrompt", "true", "useTicketCache", "true"));
        krb5.login();
        krb5.commit();
        return subject;
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("javax.security.auth.useSubjectCredsOnly", "true");
        krb5 = new Oid("1.2.840.113554.1.2.2");

        peer = args.length > 0 ? args[0]
            : ("host/" + System.getenv("LOGONSERVER").substring(2)
                    .toLowerCase(Locale.ROOT));

        System.out.println("Connecting to " + peer + "...");
        System.out.println("isNative: " + isNative);

        Subject s = krb5login();
        if (Subject.callAs(s, GetSessionKey::go) == null) {
            throw new RuntimeException("Failed");
        }
    }

    static byte[] go() throws Exception {
        var man = GSSManager.getInstance();
        var name = man.createName(peer, GSSName.NT_USER_NAME, krb5);
        var ctx = man.createContext(name, null, null, GSSContext.DEFAULT_LIFETIME);

        ctx.requestMutualAuth(false);
        var init = ctx.initSecContext(new byte[0], 0, 0);
        System.out.println(ctx.isEstablished());

        // The key for the service ticket can be used to decrypt
        // the authenticator inside AP-REQ
        for (var t : Subject.current().getPrivateCredentials(KerberosTicket.class)) {
            System.out.println("found tkt for " + t.getServer());
            var key = (EncryptionKey) t.getSessionKey();
            System.out.println(key.getAlgorithm());
            System.out.println(HexFormat.ofDelimiter(":").formatHex(key.getEncoded()));
            if (t.getServer().getName().startsWith(peer)) {
                // Per RFC 1964 1.1, init token is a SEQUENCE of an OID followed by
                // an innerContextToken, consisting of a two-byte token-id and AP-REQ.
                var der = new DerValue(init).data(); // the content of SEQUENCE
                der.getOID(); // skip the mech OID
                init = der.toByteArray(); // the rest
                var apreq = new APReq(Arrays.copyOfRange(init, 2, init.length)); // skip token-id
                var sk = new sun.security.krb5.EncryptionKey(key.getKeyType(), key.getEncoded());
                return apreq.authenticator.decrypt(sk, KeyUsage.KU_AP_REQ_AUTHENTICATOR);
            }
        }
        return null;
    }
}
