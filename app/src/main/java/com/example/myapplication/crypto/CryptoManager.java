package com.example.myapplication.crypto;

import java.io.IOException;

/**
 * The main entry point for the cryptographic library.
 * This class acts as a facade, delegating the actual encryption and decryption work
 * to the appropriate processor based on user settings and file properties.
 * It uses a strategy pattern to switch between parallel and sequential processors.
 */
public class CryptoManager implements CryptoProcessor {

    private final CryptoProcessor parallelProcessor;
    private final CryptoProcessor sequentialProcessor;

    /**
     * Constructs a CryptoManager, initializing the underlying processors.
     */
    public CryptoManager() {
        this.parallelProcessor = new ParallelProcessor();
        this.sequentialProcessor = new SequentialProcessor();
    }

    /**
     * Encrypts a file using the best available strategy based on user settings.
     *
     * @param sourceFilePath Path to the source file to be encrypted.
     * @param destFilePath   Path to the destination file to be created.
     * @param password       The password to use for key derivation.
     * @param options        The cryptographic options (algorithm, mode, etc.).
     * @param chunkSize      The size of chunks for processing.
     * @param threads        The number of threads to use. Per user spec, if this is > 1, the mode is guaranteed to be parallelizable.
     * @param listener       A listener to receive progress updates.
     * @throws Exception If an error occurs during the encryption process.
     */
    @Override
    public void encrypt(String sourceFilePath, String destFilePath, char[] password, CryptoOptions options, int chunkSize, int threads, CryptoListener listener) throws Exception {
        // As confirmed by the user, the UI layer will lock the thread count to 1 for non-parallelizable modes.
        // Therefore, we can confidently decide the strategy based on the thread count alone.
        if (threads > 1) {
            parallelProcessor.encrypt(sourceFilePath, destFilePath, password, options, chunkSize, threads, listener);
        } else {
            // All single-threaded requests are handled sequentially.
            sequentialProcessor.encrypt(sourceFilePath, destFilePath, password, options, chunkSize, 1, listener);
        }
    }

    /**
     * Decrypts a file. The manager automatically determines the correct processor
     * to use by reading the header from the source file and checking user settings.
     *
     * @param sourceFilePath Path to the source file to be decrypted.
     * @param destFilePath   Path to the destination file for the decrypted content.
     * @param password       The password used for the original encryption.
     * @param chunkSize      The size of chunks for processing.
     * @param threads        The number of threads to use for parallel processing.
     * @param listener       A listener to receive progress updates.
     * @throws Exception If any error occurs, including incorrect password or corrupted file.
     */
    @Override
    public void decrypt(String sourceFilePath, String destFilePath, char[] password, int chunkSize, int threads, CryptoListener listener) throws Exception {
        CryptoOptions options;
        try {
            options = FileHeader.peekOptions(sourceFilePath);
        } catch (IOException | ClassNotFoundException e) {
            // If peeking fails (e.g., corrupt file, not our format), we cannot determine the strategy.
            // The safest fallback is the sequential processor, which will then produce a detailed error.
            sequentialProcessor.decrypt(sourceFilePath, destFilePath, password, chunkSize, 1, listener);
            return;
        }

        // Use the parallel processor ONLY if the user wants parallel processing (threads > 1)
        // AND the file was originally encrypted with a mode that supports it.
        if (threads > 1 && options.isParallelizable()) {
            parallelProcessor.decrypt(sourceFilePath, destFilePath, password, chunkSize, threads, listener);
        } else {
            // Otherwise, fall back to the robust sequential processor.
            sequentialProcessor.decrypt(sourceFilePath, destFilePath, password, chunkSize, 1, listener);
        }
    }
}
