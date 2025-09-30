package com.example.myapplication.crypto;

public class CryptoManager implements CryptoProcessor {

    private final SequentialProcessor sequentialProcessor = new SequentialProcessor();
    private final ParallelProcessor parallelProcessor = new ParallelProcessor();

    @Override
    public void encrypt(String sourceFilePath, String destFilePath, char[] password, CryptoOptions options, int chunkSize, int threads, CryptoListener listener) throws Exception {
        listener.onLog("CryptoManager: Encrypting with " + threads + " thread(s).");
        if (threads > 1 && isParallelizable(options)) {
            parallelProcessor.encrypt(sourceFilePath, destFilePath, password, options, chunkSize, threads, listener);
        } else {
            sequentialProcessor.encrypt(sourceFilePath, destFilePath, password, options, chunkSize, 1, listener);
        }
    }

    @Override
    public void decrypt(String sourceFilePath, String destFilePath, char[] password, CryptoOptions manualOptions, int chunkSize, int threads, CryptoListener listener) throws Exception {
        listener.onLog("CryptoManager: Decrypting with " + threads + " thread(s).");

        CryptoOptions optionsToUse = manualOptions;
        boolean parallel = false;

        if (optionsToUse == null) {
            // Auto mode: peek at header to decide if parallel is possible
            try {
                optionsToUse = FileHeader.peekOptions(sourceFilePath);
                parallel = isParallelizable(optionsToUse);
            } catch (Exception e) {
                listener.onError("Failed to read file header for decryption.", e);
                return;
            }
        } else {
            // Manual mode: use provided options to decide
            parallel = isParallelizable(optionsToUse);
        }

        if (threads > 1 && parallel) {
            parallelProcessor.decrypt(sourceFilePath, destFilePath, password, manualOptions, chunkSize, threads, listener);
        } else {
            sequentialProcessor.decrypt(sourceFilePath, destFilePath, password, manualOptions, chunkSize, 1, listener);
        }
    }

    /**
     * Checks if the given crypto options are suitable for parallel processing.
     * Currently, only CTR mode is considered parallelizable.
     * @param options The crypto options to check.
     * @return true if the options allow for parallel processing, false otherwise.
     */
    private boolean isParallelizable(CryptoOptions options) {
        // Only CTR mode is stateless and allows for easy parallelization by calculating the IV for each chunk.
        // Other modes like CBC have dependencies on the previous block, making parallelization complex.
        return options.getMode() == CryptoOptions.CipherMode.CTR;
    }
}
