package com.example.myapplication.crypto;

/**
 * Defines the contract for a file encryption/decryption strategy.
 * Implementations of this interface will handle the actual cryptographic operations,
 * either sequentially or in parallel.
 */
public interface CryptoProcessor {

    /**
     * Encrypts a source file according to the given options and password.
     *
     * @param sourceFilePath The path to the file to be encrypted.
     * @param password       The password to use for deriving the encryption key.
     * @param options        The cryptographic parameters for the encryption.
     * @param chunkSize      The size of each chunk to process, in bytes.
     * @param threads        The number of threads to use for processing. If > 1, parallel processing may be used.
     * @param listener       The listener for receiving progress and status updates.
     * @throws Exception if any error occurs during the encryption process.
     */
    void encrypt(String sourceFilePath, char[] password, CryptoOptions options, int chunkSize, int threads, CryptoListener listener) throws Exception;

    /**
     * Decrypts a source file.
     * Can operate in two modes:
     * 1. Automatic Mode (manualMode = false): Reads cryptographic options from the file's header.
     *    The 'manualOptions' parameter is ignored.
     * 2. Manual Mode (manualMode = true): Uses the provided 'manualOptions' for decryption.
     *    This is useful for decrypting files from other sources that don't have a compatible header.
     *
     * @param sourceFilePath The path to the file to be decrypted.
     * @param password       The password used during the encryption of the file.
     * @param manualOptions  The cryptographic parameters to use in manual mode. Can be null if manualMode is false.
     * @param isManualMode   A boolean flag to enable or disable manual decryption mode.
     * @param chunkSize      The size of each chunk to process, in bytes.
     * @param threads        The number of threads to use for processing.
     * @param listener       The listener for receiving progress and status updates.
     * @throws Exception if any error occurs during the decryption process.
     */
    void decrypt(String sourceFilePath, char[] password, CryptoOptions manualOptions, boolean isManualMode, int chunkSize, int threads, CryptoListener listener) throws Exception;
}
