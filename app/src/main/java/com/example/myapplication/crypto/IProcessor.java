package com.example.myapplication.crypto;

public interface IProcessor {
    void encrypt(String sourcePath, String destPath, char[] password, CryptoOptions options, int chunkSize, CryptoListener listener) throws Exception;
    void decrypt(String sourcePath, String destPath, char[] password, CryptoOptions manualOptions, int chunkSize, CryptoListener listener) throws Exception;
}
