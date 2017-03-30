package com.secure.key.backup;


import com.google.gson.Gson;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;
import java.util.Random;

/**
 * Adapted from <a href="https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing">Shamir's Secret Sharing</a>.
 */
class Shamir {

    private Shamir() {

    }

    /**
     * Splits the keys into secrets that can be passed to the participants.
     *
     * @param backupKey KeyPart to backup.
     * @param participants Number of contacts that will receive a secret.
     * @param requiredParticipants Required number of secrets to recreate the keys.
     * @return Secrets for the contacts.
     */
    static String[] split(byte[] backupKey, int participants, int requiredParticipants) {
        BigInteger key = new BigInteger(backupKey);

        Random random = new SecureRandom();
        int primeBitLength = key.bitLength() + 1 + random.nextInt(10); // bitlength ensures that prime > key

        BigInteger prime = BigInteger.probablePrime(primeBitLength, random);

        BigInteger upperRange = prime.subtract(new BigInteger("1"));
        BigDecimal upperRangeDecimal = new BigDecimal(upperRange);

        BigInteger[] coefficient = new BigInteger[requiredParticipants - 1];

        for (int i = 0; i < requiredParticipants - 1; i++) {
            BigDecimal randomValue = new BigDecimal(random.nextDouble());

            coefficient[i] = upperRangeDecimal.multiply(randomValue).toBigInteger();
        }

        String[] secrets = new String[participants];

        for (int i = 0; i < participants; i++) {
            BigInteger y = key;
            BigInteger x = BigInteger.valueOf(i + 1);

            for (int exp = 1; exp < requiredParticipants; exp++) {
                y = (y.add(coefficient[exp - 1].multiply(x.pow(exp).mod(prime)).mod(prime)).mod(prime)).mod(prime);
            }

            Share share = new Share(i + 1, y, prime, requiredParticipants);
            secrets[i] = new Gson().toJson(share);
        }

        return secrets;
    }

    /**
     * Recreate the keys that were split into several secrets.
     *
     * @param serializedSecrets Received secrets from contacts.
     * @return KeyPart that were backed up.
     * @throws IllegalArgumentException Too few secrets are passed to recreate the keys.
     */
    static byte[] join(List<String> serializedSecrets) throws IllegalArgumentException {
        Share[] shares = new Share[serializedSecrets.size()];

        int i = 0;
        for (String secret : serializedSecrets) {
            shares[i++] = new Gson().fromJson(secret, Share.class);
        }

        int requiredParticipants = shares[0].getDegree();
        BigInteger prime = shares[0].getPrime();

        if (serializedSecrets.size() < requiredParticipants) {
            throw new IllegalArgumentException("Passed " + serializedSecrets.size() + " shares but " + requiredParticipants + " shares are needed!");
        }

        BigInteger key = new BigInteger("0");

        for (int j = 0; j < requiredParticipants; j++) {
            BigInteger value = shares[j].getY();
            BigInteger xj = BigInteger.valueOf(shares[j].getX());

            for (int m = 0; m < requiredParticipants; m++) {
                if (j != m) {
                    BigInteger xm = BigInteger.valueOf(shares[m].getX());
                    value = value.multiply(xm.multiply(xm.subtract(xj).modInverse(prime)).mod(prime)).mod(prime);
                }
            }

            key = key.add(value).mod(prime);
        }

        return key.toByteArray();
    }
}
