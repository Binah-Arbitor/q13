package com.example.myapplication.crypto;

/**
 * Defines the contract for a file encryption/decryption strategy.
 * Implementations of this interface will handle the actual cryptographic operations.
 */
public interface CryptoProcessor {

    /**
     * Encrypts a source file and saves it to a destination file.
     *
     * @param sourceFilePath The path to the file to be encrypted.
     * @param destFilePath   The path where the encrypted file will be saved.
     * @param password       The password to use for deriving the encryption key.
     * @param options        The cryptographic parameters for the encryption.
     * @param chunkSize      The size of each chunk to process, in bytes.
     * @param threads        The number of threads to use for processing.
     * @param listener       The listener for receiving progress and status updates.
     * @throws Exception if any error occurs during the encryption process.
     */
    void encrypt(String sourceFilePath, String destFilePath, char[] password, CryptoOptions options, int chunkSize, int threads, CryptoListener listener) throws Exception;

    /**
     * Decrypts a source file and saves the result to a destination file.
     *
     * @param sourceFilePath The path to the file to be decrypted.
     * @param destFilePath   The path where the decrypted file will be saved.
     * @param password       The password used during the encryption of the file.
     * @param manualOptions  Optional. If provided, these cryptographic parameters are used for decryption, ignoring the file header. If null, parameters are read from the file header.
     * @param chunkSize      The size of each chunk to process, in bytes.
     * @param threads        The number of threads to use for processing.
     * @param listener       The listener for receiving progress and status updates.
     * @throws Exception if any error occurs during the decryption process.
     */
    void decrypt(String sourceFilePath, String destFilePath, char[] password, CryptoOptions manualOptions, int chunkSize, int threads, CryptoListener listener) throws Exception;
}
