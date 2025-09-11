package javax.crypto.hpke;

/**
 * Standard KEM algorithms defined in RFC 9180.
 *
 * @see javax.crypto.spec.HPKEParameterSpec
 * @since 26
 */
public enum StandardKem implements Kem {
    /**
     * KEM algorithm for DHKEM(P-256, HKDF-SHA256) as defined in
     * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-key-encapsulation-mechanism">Section 7.1 of RFC 9180</a>.
     */
    DHKEM_P_256_HKDF_SHA256(0x10),
    /**
     * KEM algorithm for DHKEM(P-384, HKDF-SHA384) as defined in
     * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-key-encapsulation-mechanism">Section 7.1 of RFC 9180</a>.
     */
    DHKEM_P_384_HKDF_SHA384(0x11),
    /**
     * KEM algorithm for DHKEM(P-521, HKDF-SHA512) as defined in
     * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-key-encapsulation-mechanism">Section 7.1 of RFC 9180</a>.
     */
    DHKEM_P_521_HKDF_SHA512(0x12),
    /**
     * KEM algorithm for DHKEM(X25519, HKDF-SHA256) as defined in
     * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-key-encapsulation-mechanism">Section 7.1 of RFC 9180</a>.
     */
    DHKEM_X25519_HKDF_SHA256(0x20),
    /**
     * KEM algorithm for DHKEM(X448, HKDF-SHA512) as defined in
     * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-key-encapsulation-mechanism">Section 7.1 of RFC 9180</a>.
     */
    DHKEM_X448_HKDF_SHA512(0x21);
    ;

    private final int id;

    StandardKem(int id) {
        this.id = id;
    }

    @Override
    public int id() {
        return id;
    }
}
