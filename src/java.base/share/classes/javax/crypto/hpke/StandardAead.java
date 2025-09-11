package javax.crypto.hpke;

/**
 * Standard AEAD algorithms defined in RFC 9180.
 *
 * @see javax.crypto.spec.HPKEParameterSpec
 * @since 26
 */
public enum StandardAead implements Aead {
    /**
     * AEAD algorithm for AES-128-GCM as defined in
     * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-authenticated-encryption-wi">Section 7.3 of RFC 9180</a>.
     */
    AES_128_GCM(1),
    /**
     * AEAD algorithm for AES-256-GCM as defined in
     * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-authenticated-encryption-wi">Section 7.3 of RFC 9180</a>.
     */
    AES_256_GCM(2),
    /**
     * AEAD algorithm for ChaCha20Poly1305 as defined in
     * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-authenticated-encryption-wi">Section 7.3 of RFC 9180</a>.
     */
    CHACHA20_POLY1305(3),
    /**
     * AEAD algorithm for Export-only as defined in
     * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-authenticated-encryption-wi">Section 7.3 of RFC 9180</a>.
     */
    EXPORT_ONLY(0xffff),
    ;

    private final int id;

    StandardAead(int id) {
        this.id = id;
    }

    @Override
    public int id() {
        return id;
    }
}
