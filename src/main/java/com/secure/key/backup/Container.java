package com.secure.key.backup;

import java.security.Key;

/**
 * The container is responsible for generating the private and public key. It splits the
 * private key into multiple {@link KeyPart key parts}. New backups can be created and
 * restored.
 */
public interface Container {

    /**
     * Specify the content of this container.
     *
     * @param name Name of the container.
     */
    void setName(String name);

    /**
     * Set the amount of {@link KeyPart key parts} that will be necessary to restore a backup
     * that was created by this container.
     *
     * @param minimum Minimum key parts needed to restore a backup.
     */
    void setMinimumRecoverParts(int minimum);

    /**
     * Get the minimum count of key parts needed to reveal backups created by this container.
     */
    int getMinimumRecoverParts();

    /**
     * Set the amount of {@link KeyPart key parts} that will be created from the private key.
     *
     * @param total Count of key parts.
     */
    void setTotalParts(int total);

    /**
     * Get the total count of key parts that were created of the key that belongs to this container.
     */
    int getTotalRecoverParts();

    /**
     * Split the private key of this container into the amount of pieces
     * set via {@link #setTotalParts(int)}. In addition, the amount of the the minimum
     * pieces needed to recreate the key must be specified via
     * {@link #setMinimumRecoverParts(int)}.
     *
     * @return The key parts.
     */
    KeyPart[] splitPrivateKey();

    /**
     * Get the public key of this container.
     *
     * @return Public key. Null if {@link #splitPrivateKey()} was not called before.
     */
    Key getPublicKey();

    /**
     * Get the name of this container.
     *
     * @return Name of the container.
     */
    String getName();

    /**
     * Restore a backup that was created by this container.
     *
     * @param keyParts Key parts of the private key.
     * @param encryptedBackup Backup to restore.
     * @return Decrypted backup.
     */
    String restoreBackup(KeyPart[] keyParts, String encryptedBackup);

    /**
     * Create a new backup that can only be decrypted by the private key of this container.
     *
     * @return A new backup.
     */
    Backup newBackup();
}
