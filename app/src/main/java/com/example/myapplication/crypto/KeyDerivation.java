package com.example.myapplication.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class KeyDerivation {

    private static final int ITERATION_COUNT = 65536;

    public static SecretKey deriveKey(char[] password, byte[] salt, CryptoOptions.Kdf kdf, CryptoOptions.KeyLength keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password, salt, ITERATION_COUNT, keyLength.getBits());
        SecretKeyFactory factory = SecretKeyFactory.getInstance(kdf.name());
        return factory.generateSecret(spec);
    }

    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }
}
