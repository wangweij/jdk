package javax.crypto.hpke;

/**
 * A KEM algorithm used in HPKE.
 *
 * @see javax.crypto.spec.HPKEParameterSpec
 * @since 26
 */
public interface Kem {
    /**
     * {@return the algorithm identifier}
     */
    int id();

    /**
     * Returns a KEM algorithm with the specified algorithm identifier.
     * <p>
     * This method is useful if the algorithm for the identifier is not
     * defined as a {@link StandardKem} field.
     *
     * @param id the numeric algorithm identifier
     * @return an KEM algorithm
     * @throws IllegalArgumentException if {@code id} is smaller than 0 or
     *      larger than 65535.
     */
    static Kem from(int id) {
        return new SimpleId(id);
    }
}
