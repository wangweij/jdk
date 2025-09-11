package javax.crypto.hpke;

record SimpleId(int id) implements Aead, Kdf, Kem {
    SimpleId {
        if (id < 0 || id > 65535) {
            throw new IllegalArgumentException(
                    "id must be between 0 and 65535, inclusive");
        }
    }
}
