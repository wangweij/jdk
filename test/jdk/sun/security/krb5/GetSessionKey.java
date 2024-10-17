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

import com.sun.security.jgss.ExtendedGSSContext;
import com.sun.security.jgss.InquireType;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.MessageProp;
import sun.security.jgss.GSSUtil;
import sun.security.krb5.internal.APReq;
import sun.security.krb5.internal.crypto.KeyUsage;
import sun.security.krb5.internal.crypto.dk.AesDkCrypto;
import sun.security.krb5.internal.crypto.dk.DkCrypto;
import sun.security.util.DerValue;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.*;
import javax.security.auth.kerberos.EncryptionKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Locale;

public class GetSessionKey {

    public static class CB implements CallbackHandler {
        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (var cb : callbacks) {
                if (cb instanceof NameCallback ncb) {
                    ncb.setName(System.getenv("USER"));
                } else if (cb instanceof PasswordCallback pcb) {
                    pcb.setPassword(System.getenv("PASSADMIN").toCharArray());
                }
            }
        }
    }

    public static void main(String[] args) throws Exception {

        System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
        Security.setProperty("auth.login.defaultCallbackHandler", CB.class.getName());

        String peer = null;

        var inf = false;
        if (args.length > 0) {
            var pos = 0;
            if (args[0].equals("-inf")) {
                inf = true;
                pos = 1;
            }
            if (args.length > pos) {
                peer = args[pos];
            }
        }
        if (peer == null) {
            peer = "host/" + System.getenv("LOGONSERVER").substring(2).toLowerCase(Locale.ROOT);
        }
        System.out.println("Connecting to " + peer + "...");

        if (inf) {
            for (int i = 0; i < Integer.MAX_VALUE; i++) {
                var man = GSSManager.getInstance();
                var name = man.createName(peer, GSSName.NT_USER_NAME, GSSUtil.GSS_KRB5_MECH_OID);
                var ctx = (ExtendedGSSContext) man.createContext(name, null, null, GSSContext.DEFAULT_LIFETIME);
                ctx.requestMutualAuth(false);
                var init = ctx.initSecContext(new byte[0], 0, 0);
                var key = (EncryptionKey)ctx.inquireSecContext(InquireType.KRB5_GET_SESSION_KEY_EX);
                var key2 = (EncryptionKey)ctx
                        .inquireSecContext(InquireType.KRB5_GET_ODBC_SESSION_KEY);
                if (i % 1000 == 0) System.err.print('*');
            }
        }
        var man = GSSManager.getInstance();
        var name = man.createName(peer, GSSName.NT_USER_NAME, GSSUtil.GSS_KRB5_MECH_OID);
        var ctx = (ExtendedGSSContext) man.createContext(name, null, null, GSSContext.DEFAULT_LIFETIME);

        ctx.requestMutualAuth(false);
        var init = ctx.initSecContext(new byte[0], 0, 0);
        System.out.println(ctx.isEstablished());

        // The key for the context can be used to decrypt a wrap token
        var key = (EncryptionKey)ctx.inquireSecContext(InquireType.KRB5_GET_SESSION_KEY_EX);
        System.out.println(key.getAlgorithm());
        System.out.println(HexFormat.ofDelimiter(":").formatHex(key.getEncoded()));

        var msg = "hello you fool".getBytes(StandardCharsets.UTF_8);
        var token = ctx.wrap(msg, 0, msg.length, new MessageProp(true));

        int rrc = token[7];
        var nt = token.clone();
        System.arraycopy(token, 16 + rrc, nt, 16, token.length - 16 - rrc);
        System.arraycopy(token, 16, nt, token.length - rrc, rrc);
        var ct = Arrays.copyOfRange(nt, 16, nt.length - 12);

        var c = new AesDkCrypto(key.getEncoded().length * 8);
        var m = DkCrypto.class.getDeclaredMethod("dk", byte[].class, byte[].class);
        m.setAccessible(true);
        byte[] constant = new byte[] {0, 0, 0, 24, (byte)0xaa};
        byte[] Ke = (byte[])m.invoke(c, key.getEncoded(), constant);
        Cipher cipher = Cipher.getInstance("AES/CTS/NoPadding");
        SecretKeySpec secretKey = new SecretKeySpec(Ke, "AES");
        IvParameterSpec encIv = new IvParameterSpec(new byte[16], 0, 16);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, encIv);
        var pt = cipher.doFinal(ct);
        pt = Arrays.copyOfRange(pt, 16, pt.length - 16);
        System.out.println(new String(pt, StandardCharsets.ISO_8859_1));
        if (!Arrays.equals(pt, msg)) {
            throw new RuntimeException("Fail");
        }

        // The key for the service ticket can be used to decrypt
        // the authenticator inside AP-REQ
        var key2 = (EncryptionKey)ctx
                .inquireSecContext(InquireType.KRB5_GET_ODBC_SESSION_KEY);
        System.out.println(key2.getAlgorithm());
        System.out.println(HexFormat.ofDelimiter(":").formatHex(key2.getEncoded()));

        // Per RFC 1964 1.1, init token is a SEQUENCE of an OID followed by
        // an innerContextToken, consisting of a two-byte token-id and AP-REQ.
        var der = new DerValue(init).data(); // the content of SEQUENCE
        der.getOID(); // skip the mech OID
        init = der.toByteArray(); // the rest
        var apreq = new APReq(Arrays.copyOfRange(init, 2, init.length)); // skip token-id
        var sk = new sun.security.krb5.EncryptionKey(key2.getKeyType(), key2.getEncoded());
        apreq.authenticator.decrypt(sk, KeyUsage.KU_AP_REQ_AUTHENTICATOR);
    }
}
