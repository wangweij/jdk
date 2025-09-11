package javax.crypto.hpke;

/**
 * An AEAD algorithm used in HPKE.
 *
 * @see javax.crypto.spec.HPKEParameterSpec
 * @since 26
 */
public interface Aead {
    /**
     * {@return the algorithm identifier}
     */
    int id();

    /**
     * Returns an AEAD algorithm with the specified algorithm identifier.
     * <p>
     * This method is useful if the algorithm for the identifier is not
     * defined as a {@link StandardAead} field.
     *
     * @param id the numeric algorithm identifier
     * @return an AEAD algorithm
     * @throws IllegalArgumentException if {@code id} is smaller than 0 or
     *      larger than 65535.
     */
    static Aead from(int id) {
        return new SimpleId(id);
    }
}
