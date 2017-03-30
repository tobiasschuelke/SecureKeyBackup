package com.secure.key.backup;


import java.math.BigInteger;

/**
 * Used to store information of a point of the function that will be created by {@link Shamir}.
 */
class Share {
    private int x;
    private BigInteger y;
    private BigInteger prime;
    private int degree;

    Share() {

    }

    Share(int x, BigInteger y, BigInteger prime, int degree) {
        this.x = x;
        this.y = y;
        this.prime = prime;
        this.degree = degree;
    }

    int getX() {
        return x;
    }

    BigInteger getY() {
        return y;
    }

    BigInteger getPrime() {
        return prime;
    }

    int getDegree() {
        return degree;
    }
}
