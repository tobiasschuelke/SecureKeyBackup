package com.secure.key.backup;

/**
 * Part of a private key of a {@link Container}.
 */
public interface KeyPart {

    /**
     * Get the key part to transmit it to others.
     *
     * @return Key part as a String.
     */
    String getKeyPart();

    /**
     * Indicated whether this key part belongs the user or another person.
     *
     * @return True if this key part belongs to the current user.
     */
    boolean isForeign();

}
