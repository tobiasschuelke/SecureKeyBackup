package com.secure.key.backup;

/**
 *  Encrypts and decrypts a secret.
 */
public interface Backup {

    /**
     * Set the name of this backup. This can be, for example, the name
     * of an E-Mail provider if the private key for E-Mails should be
     * backed up.
     *
     * @param name Name of the backup.
     */
    void setName(String name);

    /**
     * Get the name of this backup.
     *
     * @return Name of this backup.
     */
    String getName();

    /**
     * Encrypt a secret.
     *
     * @param secret Secret to back up.
     */
    void encrypt(String secret);

    /**
     * Decrypt a secret.
     *
     * @param encryptedSecret Encrypted backup.
     */
    void decrypt(String encryptedSecret);


    /**
     * Receive the decrypted secret.
     *
     * @return Secret in plain text. Returns null if secret could not be decrypted.
     */
    String getDecryptedData();

    /**
     * Receive the encrypted secret.
     *
     * @return Encrypted secret.
     */
    String getEncryptedData();
}
