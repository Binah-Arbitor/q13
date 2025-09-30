package com.example.myapplication.crypto;

import java.security.SecureRandom;

public class Utils {

    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * Generates a specified number of cryptographically secure random bytes.
     *
     * @param numBytes The number of bytes to generate.
     * @return A byte array containing the random bytes.
     */
    public static byte[] generateRandomBytes(int numBytes) {
        if (numBytes <= 0) {
            throw new IllegalArgumentException("Number of bytes must be positive.");
        }
        byte[] randomBytes = new byte[numBytes];
        secureRandom.nextBytes(randomBytes);
        return randomBytes;
    }
}
