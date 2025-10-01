package com.example.myapplication.crypto;

public interface CryptoProcessor {

    default void encrypt(String sourcePath, String destPath, char[] password, CryptoOptions options, int chunkSize, CryptoListener listener) throws Exception {
        encrypt(sourcePath, destPath, password, options, chunkSize, 1, listener);
    }

    void encrypt(String sourcePath, String destPath, char[] password, CryptoOptions options, int chunkSize, int threads, CryptoListener listener) throws Exception;

    default void decrypt(String sourcePath, String destPath, char[] password, CryptoOptions manualOptions, int chunkSize, CryptoListener listener) throws Exception {
        decrypt(sourcePath, destPath, password, manualOptions, chunkSize, 1, listener);
    }

    void decrypt(String sourcePath, String destPath, char[] password, CryptoOptions manualOptions, int chunkSize, int threads, CryptoListener listener) throws Exception;

}
