package com.example.myapplication.crypto;

public class CryptoManager {

    public void encrypt(String sourcePath, String destPath, char[] password, CryptoOptions options, int chunkSize, int threads, CryptoListener listener) throws Exception {
        CryptoProcessor processor;
        if (threads > 1 && options.getMode().isStreamMode()) {
            processor = new ParallelProcessor();
            processor.encrypt(sourcePath, destPath, password, options, chunkSize, threads, listener);
        } else {
            processor = new SequentialProcessor();
            // Always pass 1 thread for sequential processing
            processor.encrypt(sourcePath, destPath, password, options, chunkSize, 1, listener);
        }
    }

    public void decrypt(String sourcePath, String destPath, char[] password, CryptoOptions manualOptions, int chunkSize, int threads, CryptoListener listener) throws Exception {
        CryptoProcessor processor;
        // Determine if we can use parallel processing
        boolean canParallel = threads > 1 && (manualOptions != null ? manualOptions.getMode().isStreamMode() : isEncryptedFileStreamable(sourcePath));

        if (canParallel) {
            processor = new ParallelProcessor();
            processor.decrypt(sourcePath, destPath, password, manualOptions, chunkSize, threads, listener);
        } else {
            processor = new SequentialProcessor();
            // Always pass 1 thread for sequential processing
            processor.decrypt(sourcePath, destPath, password, manualOptions, chunkSize, 1, listener);
        }
    }

    /**
     * Helper method to check if an encrypted file uses a streamable cipher mode.
     * This is a simplified check and assumes the header can be read.
     */
    private boolean isEncryptedFileStreamable(String sourcePath) {
        try (java.io.FileInputStream fis = new java.io.FileInputStream(sourcePath)) {
            FileHeader header = FileHeader.fromStream(fis);
            return header.getOptions().getMode().isStreamMode();
        } catch (Exception e) {
            // If we can't read the header, we can't determine the mode, so we default to sequential.
            return false;
        }
    }
}
