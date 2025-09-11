/*
 * Copyright (c) 2025, Oracle and/or its affiliates. All rights reserved.
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
package javax.crypto.spec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.hpke.Aead;
import javax.crypto.hpke.Kdf;
import javax.crypto.hpke.Kem;
import java.nio.charset.StandardCharsets;
import java.security.AsymmetricKey;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * This immutable class specifies the set of parameters used with a {@code Cipher} for the
 * <a href="https://www.rfc-editor.org/info/rfc9180">Hybrid Public Key Encryption</a>
 * (HPKE) algorithm. HPKE is a public key encryption scheme for encrypting
 * arbitrary-sized plaintexts with a recipient's public key. It combines a key
 * encapsulation mechanism (KEM), a key derivation function (KDF), and an
 * authenticated encryption with additional data (AEAD) cipher.
 * <p>
 * The <a href="{@docRoot}/../specs/security/standard-names.html#cipher-algorithms">
 * standard algorithm name</a> for the cipher is "HPKE". Unlike most other
 * ciphers, HPKE is not expressed as a transformation string of the form
 * "algorithm/mode/padding". Therefore, the argument to {@code Cipher.getInstance}
 * must be the single algorithm name "HPKE".
 * <p>
 * In HPKE, the sender's {@code Cipher} is always initialized with the
 * recipient's public key in {@linkplain Cipher#ENCRYPT_MODE encrypt mode},
 * while the recipient's {@code Cipher} object is initialized with its own
 * private key in {@linkplain Cipher#DECRYPT_MODE decrypt mode}.
 * <p>
 * An {@code HPKEParameterSpec} object must be provided at HPKE
 * {@linkplain Cipher#init(int, Key, AlgorithmParameterSpec) cipher initialization}.
 * <p>
 * The {@link #of(Kem, Kdf, Aead)} static method returns an
 * {@code HPKEParameterSpec} constructed with the given KEM, KDF, and AEAD
 * algorithm objects. Each algorithm is represented by an interface
 * ({@code Kem}, {@code Kdf}, or {@code Aead}) that provides an
 * {@code id()} method returning its numeric identifier. These identifiers
 * are defined in
 * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#section-7">Section 7</a>
 * of RFC 9180 and the
 * <a href="https://www.iana.org/assignments/hpke/hpke.xhtml">IANA HPKE page</a>.
 * <p>
 * Once an {@code HPKEParameterSpec} object is created, additional methods
 * are available to generate new {@code HPKEParameterSpec} objects with
 * different features:
 * <ul>
 * <li>
 * Application-supplied information can be provided using the
 * {@link #withInfo(byte[])} method by both sides.
 * <li>
 * To authenticate using a pre-shared key ({@code mode_psk}), the
 * pre-shared key and its identifier must be provided using the
 * {@link #withPsk(SecretKey, byte[])} method by both sides.
 * <li>
 * To authenticate using an asymmetric key ({@code mode_auth}),
 * the asymmetric keys must be provided using the {@link #withAuthKey(AsymmetricKey)}
 * method. Precisely, the sender must call this method with its own private key
 * and the recipient must call it with the sender's public key.
 * <li>
 * To authenticate using both a PSK and an asymmetric key
 * ({@code mode_auth_psk}), both {@link #withAuthKey(AsymmetricKey)} and
 * {@link #withPsk(SecretKey, byte[])} methods must be called as described above.
 * <li>
 * In HPKE, a shared secret is negotiated during the KEM step and a key
 * encapsulation message must be transmitted from the sender to the recipient
 * so that the recipient can recover this shared secret. On the sender side,
 * after the cipher is initialized, the key encapsulation message can be
 * retrieved using the {@link Cipher#getIV()} method. On the recipient side,
 * this message must be supplied as part of an {@code HPKEParameterSpec}
 * object obtained from the {@link #withEncapsulation(byte[])} method.
 * </ul>
 * For successful interoperability, both sides need to have identical algorithm
 * identifiers, and supply identical
 * {@code info}, {@code psk}, and {@code psk_id} or matching authentication
 * keys if provided. For details about HPKE modes, refer to
 * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#section-5">Section 5</a>
 * of RFC 9180.
 * <p>
 * If an HPKE cipher is initialized without parameters, an
 * {@code InvalidKeyException} is thrown.
 * <p>
 * At HPKE cipher initialization, if no HPKE implementation supports the
 * provided key type, an {@code InvalidKeyException} is thrown. If the provided
 * {@code HPKEParameterSpec} is not accepted by any HPKE implementation,
 * an {@code InvalidAlgorithmParameterException} is thrown by the
 * {@code init} method. The following are cases of invalid parameters:
 * <ul>
 * <li> An algorithm identifier is unsupported or does not match the provided key type.
 * <li> The key encapsulation message is not provided on the recipient side.
 * <li> An attempt to use {@code withAuthKey(key)} is made with an incompatible key.
 * <li> An attempt to use {@code withAuthKey(key)} is made but {@code mode_auth}
 *      or {@code mode_auth_psk} is not supported by the KEM used.
 * </ul>
 * After initialization, both the sender and recipient can process multiple
 * messages in sequence with repeated {@code doFinal} calls, optionally preceded
 * by one or more {@code updateAAD} and {@code update}. Each {@code doFinal}
 * performs a complete HPKE encryption or decryption operation using a distinct
 * IV derived from an internal sequence counter, as specified in
 * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2">Section 5.2</a>
 * of RFC 9180. On the recipient side, each {@code doFinal} call must correspond
 * to exactly one complete ciphertext, and the number and order of calls must
 * match those on the sender side. This differs from the direct use of an AEAD
 * cipher, where the caller must provide a fresh IV and reinitialize the cipher
 * for each message. By managing IVs internally, HPKE allows a single
 * initialization to support multiple messages while still ensuring IV
 * uniqueness and preserving AEAD security guarantees.
 * <p>
 * This example shows a sender and a recipient using HPKE to securely exchange
 * messages with an X25519 key pair.
 * {@snippet lang=java class="PackageSnippets" region="hpke-spec-example"}
 *
 * @spec https://www.rfc-editor.org/info/rfc9180
 *      RFC 9180: Hybrid Public Key Encryption
 * @spec security/standard-names.html
 *      Java Security Standard Algorithm Names
 * @since 26
 */
public final class HPKEParameterSpec implements AlgorithmParameterSpec {

    private final int kem_id;
    private final int kdf_id;
    private final int aead_id;
    private final byte[] info; // never null, can be empty
    private final SecretKey psk; // null if not used
    private final byte[] psk_id; // never null, can be empty
    private final AsymmetricKey kS; // null if not used
    private final byte[] encapsulation; // null if none

    // Note: this constructor does not clone array arguments.
    private HPKEParameterSpec(int kem_id, int kdf_id, int aead_id, byte[] info,
            SecretKey psk, byte[] psk_id, AsymmetricKey kS, byte[] encapsulation) {
        this.kem_id = kem_id;
        this.kdf_id = kdf_id;
        this.aead_id = aead_id;
        this.info = info;
        this.psk = psk;
        this.psk_id = psk_id;
        this.kS = kS;
        this.encapsulation = encapsulation;
    }

    /**
     * A factory method to create a new {@code HPKEParameterSpec} object with
     * specified KEM, KDF, and AEAD algorithms in {@code mode_base} with an
     * empty {@code info}.
     *
     * @param kem the KEM algorithm
     * @param kdf the KDF algorithm
     * @param aead the AEAD algorithm
     * @return a new {@code HPKEParameterSpec} object
     * @throws IllegalArgumentException if any input algorithm has an identifier
     *      which is out of range (must be between 0 and 65535, inclusive).
     */
    public static HPKEParameterSpec of(Kem kem, Kdf kdf, Aead aead) {
        if (kem.id() < 0 || kem.id() > 65535) {
            throw new IllegalArgumentException("Invalid kem_id: " + kem + " " + kem.id());
        }
        if (kdf.id() < 0 || kdf.id() > 65535) {
            throw new IllegalArgumentException("Invalid kdf_id: " + kdf + " " + kdf.id());
        }
        if (aead.id() < 0 || aead.id() > 65535) {
            throw new IllegalArgumentException("Invalid aead_id: " + aead + " " + aead.id());
        }
        return new HPKEParameterSpec(kem.id(), kdf.id(), aead.id(),
                new byte[0], null, new byte[0], null, null);
    }

    /**
     * Creates a new {@code HPKEParameterSpec} object with the specified
     * {@code info} value.
     * <p>
     * For interoperability, RFC 9180 Section 7.2.1 recommends limiting
     * this value to a maximum of 64 bytes.
     *
     * @param info application-supplied information.
     *      The contents of the array are copied to protect
     *      against subsequent modification.
     * @return a new {@code HPKEParameterSpec} object
     * @throws NullPointerException if {@code info} is {@code null}
     * @throws IllegalArgumentException if {@code info} is empty.
     */
    public HPKEParameterSpec withInfo(byte[] info) {
        Objects.requireNonNull(info);
        if (info.length == 0) {
            throw new IllegalArgumentException("info is empty");
        }
        return new HPKEParameterSpec(kem_id, kdf_id, aead_id,
                info.clone(), psk, psk_id, kS, encapsulation);
    }

    /**
     * Creates a new {@code HPKEParameterSpec} object with the specified
     * {@code psk} and {@code psk_id} values.
     * <p>
     * RFC 9180 Section 5.1.2 requires the PSK MUST have at least 32 bytes
     * of entropy. For interoperability, RFC 9180 Section 7.2.1 recommends
     * limiting the key size and identifier length to a maximum of 64 bytes.
     *
     * @param psk pre-shared key
     * @param psk_id identifier for PSK. The contents of the array are copied
     *               to protect against subsequent modification.
     * @return a new {@code HPKEParameterSpec} object
     * @throws NullPointerException if {@code psk} or {@code psk_id} is {@code null}
     * @throws IllegalArgumentException if {@code psk} is shorter than 32 bytes
     *                                  or {@code psk_id} is empty
     */
    public HPKEParameterSpec withPsk(SecretKey psk, byte[] psk_id) {
        Objects.requireNonNull(psk);
        Objects.requireNonNull(psk_id);
        if (psk_id.length == 0) {
            throw new IllegalArgumentException("psk_id is empty");
        }
        if ("RAW".equalsIgnoreCase(psk.getFormat())) {
            // We can only check when psk is extractable. We can only
            // check the length and not the real entropy size
            var keyBytes = psk.getEncoded();
            assert keyBytes != null;
            Arrays.fill(keyBytes, (byte)0);
            if (keyBytes.length < 32) {
                throw new IllegalArgumentException("psk is too short");
            }
        }
        return new HPKEParameterSpec(kem_id, kdf_id, aead_id,
                info, psk, psk_id.clone(), kS, encapsulation);
    }

    /**
     * Creates a new {@code HPKEParameterSpec} object with the specified
     * key encapsulation message value that will be used by the recipient.
     *
     * @param encapsulation the key encapsulation message.
     *      The contents of the array are copied to protect against
     *      subsequent modification.
     *
     * @return a new {@code HPKEParameterSpec} object
     * @throws NullPointerException if {@code encapsulation} is {@code null}
     */
    public HPKEParameterSpec withEncapsulation(byte[] encapsulation) {
        return new HPKEParameterSpec(kem_id, kdf_id, aead_id,
                info, psk, psk_id, kS,
                Objects.requireNonNull(encapsulation).clone());
    }

    /**
     * Creates a new {@code HPKEParameterSpec} object with the specified
     * authentication key value.
     * <p>
     * Note: this method does not check whether the KEM supports
     * {@code mode_auth} or {@code mode_auth_psk}. If the resulting object is
     * used to initialize an HPKE cipher with an unsupported mode, an
     * {@code InvalidAlgorithmParameterException} will be thrown at that time.
     *
     * @param kS the authentication key
     * @return a new {@code HPKEParameterSpec} object
     * @throws NullPointerException if {@code kS} is {@code null}
     */
    public HPKEParameterSpec withAuthKey(AsymmetricKey kS) {
        return new HPKEParameterSpec(kem_id, kdf_id, aead_id,
                info, psk, psk_id,
                Objects.requireNonNull(kS),
                encapsulation);
    }

    /**
     * {@return the algorithm identifier for KEM }
     */
    public int kem_id() {
        return kem_id;
    }

    /**
     * {@return the algorithm identifier for KDF }
     */
    public int kdf_id() {
        return kdf_id;
    }

    /**
     * {@return the algorithm identifier for AEAD }
     */
    public int aead_id() {
        return aead_id;
    }

    /**
     * {@return a copy of the application-supplied information, empty if none}
     */
    public byte[] info() {
        return info.clone();
    }

    /**
     * {@return pre-shared key, {@code null} if none}
     */
    public SecretKey psk() {
        return psk;
    }

    /**
     * {@return a copy of the identifier for PSK, empty if none}
     */
    public byte[] psk_id() {
        return psk_id.clone();
    }

    /**
     * {@return the key for authentication, {@code null} if none}
     */
    public AsymmetricKey authKey() {
        return kS;
    }

    /**
     * {@return a copy of the key encapsulation message, {@code null} if none}
     */
    public byte[] encapsulation() {
        return encapsulation == null ? null : encapsulation.clone();
    }

    @Override
    public String toString() {
        return "HPKEParameterSpec{" +
                "kem_id=" + kem_id +
                ", kdf_id=" + kdf_id +
                ", aead_id=" + aead_id +
                ", info=" + bytesToString(info) +
                ", " + (psk == null
                        ? (kS == null ? "mode_base" : "mode_auth")
                        : (kS == null ? "mode_psk" : "mode_auth_psk")) + "}";
    }

    // Returns a human-readable representation of a byte array.
    private static String bytesToString(byte[] input) {
        if (input.length == 0) {
            return "(empty)";
        } else {
            for (byte b : input) {
                if (b < 0x20 || b > 0x7E || b == '"') {
                    // Non-ASCII or control characters are hard to read, and
                    // `"` requires character escaping. If any of these are
                    // present, return only the HEX representation.
                    return HexFormat.of().formatHex(input);
                }
            }
            // Otherwise, all characters are printable and safe.
            // Return both HEX and ASCII representations.
            return HexFormat.of().formatHex(input)
                    + " (\"" + new String(input, StandardCharsets.US_ASCII) + "\")";
        }
    }
}
