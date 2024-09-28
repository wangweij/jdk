/*
 * Copyright (c) 2023, Oracle and/or its affiliates. All rights reserved.
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
import sun.security.krb5.internal.crypto.dk.AesDkCrypto;
import sun.security.krb5.internal.crypto.dk.DkCrypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.kerberos.EncryptionKey;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

public class GetSessionKey {

    public static void main(String[] args) throws Exception {

        System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");

        var man = GSSManager.getInstance();
        var name = man.createName(args[0], GSSName.NT_USER_NAME, GSSUtil.GSS_KRB5_MECH_OID);
        var ctx = man.createContext(name, null, null, GSSContext.DEFAULT_LIFETIME);
        ctx.requestMutualAuth(false);
        ctx.initSecContext(new byte[0], 0, 0);
        System.out.println(ctx.isEstablished());
        var msg = "hello you fool".getBytes(StandardCharsets.UTF_8);
        var token = ctx.wrap(msg, 0, msg.length, new MessageProp(true));

        int rrc = token[7];
        var nt = token.clone();
        System.arraycopy(token, 16 + rrc, nt, 16, token.length - 16 - rrc);
        System.arraycopy(token, 16, nt, token.length - rrc, rrc);
        var ct = Arrays.copyOfRange(nt, 16, nt.length - 12);

        var key = (EncryptionKey)(((ExtendedGSSContext)ctx)
                .inquireSecContext(InquireType.KRB5_GET_SESSION_KEY_EX));
        System.out.println(key.getAlgorithm());
        System.out.println(HexFormat.ofDelimiter(":").formatHex(key.getEncoded()));

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
    }
}
