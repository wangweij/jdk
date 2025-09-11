package javax.crypto.hpke;

/**
 * A KDF algorithm used in HPKE.
 *
 * @see javax.crypto.spec.HPKEParameterSpec
 * @since 26
 */
public interface Kdf {
    /**
     * {@return the algorithm identifier}
     */
    int id();

    /**
     * Returns a KDF algorithm with the specified algorithm identifier.
     * <p>
     * This method is useful if the algorithm for the identifier is not
     * defined as a {@link StandardKdf} field.
     *
     * @param id the numeric algorithm identifier
     * @return an KDF algorithm
     * @throws IllegalArgumentException if {@code id} is smaller than 0 or
     *      larger than 65535.
     */
    static Kdf from(int id) {
        return new SimpleId(id);
    }
}
