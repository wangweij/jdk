package javax.crypto.hpke;

/**
 * Standard KDF algorithms defined in RFC 9180.
 *
 * @see javax.crypto.spec.HPKEParameterSpec
 * @since 26
 */
public enum StandardKdf implements Kdf {
    /**
     * KDF algorithm for HKDF-SHA256 as defined in
     * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-key-derivation-functions-kd">Section 7.2 of RFC 9180</a>.
     */
    HKDF_SHA256(1),
    /**
     * KDF algorithm for HKDF-SHA384 as defined in
     * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-key-derivation-functions-kd">Section 7.2 of RFC 9180</a>.
     */
    HKDF_SHA384(2),
    /**
     * KDF algorithm for HKDF-SHA512 as defined in
     * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-key-derivation-functions-kd">Section 7.2 of RFC 9180</a>.
     */
    HKDF_SHA512(3),
    ;

    private final int id;

    StandardKdf(int id) {
        this.id = id;
    }

    @Override
    public int id() {
        return id;
    }
}
