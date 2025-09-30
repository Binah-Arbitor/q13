package com.example.myapplication.crypto;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;

public class KeyDerivation {

    private static final int ITERATION_COUNT = 65536;

    public static SecretKeySpec deriveKey(char[] password, byte[] salt, CryptoOptions.Kdf kdf, CryptoOptions.KeyLength keyLength, boolean forXts) throws Exception {
        // For XTS, the derived key is split into two keys, so we need to derive twice the length.
        int derivedKeyLength = forXts ? keyLength.getBits() * 2 : keyLength.getBits();

        KeySpec spec = new PBEKeySpec(password, salt, ITERATION_COUNT, derivedKeyLength);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(kdf.name());
        byte[] derivedKeyBytes = factory.generateSecret(spec).getEncoded();

        // The AES key for SecretKeySpec is just the first part of the derived bytes.
        // For XTS, the full derived key is used by the cipher implementation internally.
        return new SecretKeySpec(derivedKeyBytes, 0, keyLength.getBytes(), "AES");
    }
}
