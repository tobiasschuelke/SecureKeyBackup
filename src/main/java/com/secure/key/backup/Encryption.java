package com.secure.key.backup;

import org.spongycastle.jce.provider.BouncyCastleProvider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * This class generates keys, encrypts and decrypts secrets using the
 * <a href="https://github.com/rtyley/spongycastle">Spongy Castle</a> library.
 * Keys are generated with elliptic curves and secrets encrypted with AES.
 */
final class Encryption {
    private static final String PROVIDER = "BC";
    private static final String ALGORITHM = "EC";
    private static final String ALGORITHM_SYMMETRIC = "ECIESwithAES-CBC";
    private static final String EC_PARAM_SPEC = "secp256r1";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Generates a public and private key pair.
     *
     * @return Array: first item is a private key, second item is a public key
     */
    static Key[] generateKeys() {
        Key[] keys = new Key[2];

        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);

            ECGenParameterSpec ecParams = new ECGenParameterSpec(EC_PARAM_SPEC);

            generator.initialize(ecParams, new SecureRandom());
            KeyPair keyPair = generator.generateKeyPair();

            keys[0] = keyPair.getPrivate();
            keys[1] = keyPair.getPublic();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        return keys;
    }

    /**
     * Encrypts a secret with passed key. If encryption does not work, null will be returned.
     *
     * @see #decrypt(PrivateKey, byte[])
     *
     * @param key       Public key used to encrypt the secret.
     * @param secret    Bytes to encrypt.
     * @return          Encrypted secret or null.
     */
    static byte[] encrypt(PublicKey key, byte[] secret) {
        byte[] encrypted = null;

        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM_SYMMETRIC);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            encrypted = cipher.doFinal(secret);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | InvalidKeyException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        return encrypted;
    }

    /**
     * Decrypts a secret with passed key. If decryption does not work, null will be returned.
     *
     * @see #encrypt(PublicKey, byte[])
     *
     * @param key               Private key used to decrypt the secret.
     * @param encryptedSecret   Encrypted secret from {@link #encrypt(PublicKey, byte[])}.
     * @return                  Original secret or null.
     */
    static byte[] decrypt(PrivateKey key, byte[] encryptedSecret) {
        byte[] secret = null;

        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM_SYMMETRIC);
            cipher.init(Cipher.DECRYPT_MODE, key);
            secret = cipher.doFinal(encryptedSecret);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return secret;
    }

    static PublicKey getPublicKey(byte[] publicKey) {
        try {
            return KeyFactory.getInstance(ALGORITHM, PROVIDER).generatePublic(new X509EncodedKeySpec(publicKey));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }

        return null;
    }

    static PrivateKey getPrivateKey(byte[] privateKey) {
        try {
            return KeyFactory.getInstance(ALGORITHM, PROVIDER).generatePrivate(new PKCS8EncodedKeySpec(privateKey));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }

        return null;
    }
}
