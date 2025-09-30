package com.example.myapplication.crypto;

public class CryptoManager {

    public void encrypt(String sourcePath, String destPath, char[] password, CryptoOptions options, int chunkSize, int threads, CryptoListener listener) throws Exception {
        CryptoProcessor processor;
        if (threads > 1 && options.getMode().isStreamMode()) {
            processor = new ParallelProcessor();
            ((ParallelProcessor) processor).encrypt(sourcePath, destPath, password, options, chunkSize, threads, listener);
        } else {
            processor = new SequentialProcessor();
            processor.encrypt(sourcePath, destPath, password, options, chunkSize, listener);
        }
    }

    public void decrypt(String sourcePath, String destPath, char[] password, CryptoOptions manualOptions, int chunkSize, int threads, CryptoListener listener) throws Exception {
        CryptoProcessor processor;
        if (threads > 1 && (manualOptions == null || manualOptions.getMode().isStreamMode())) {
            processor = new ParallelProcessor();
            ((ParallelProcessor) processor).decrypt(sourcePath, destPath, password, manualOptions, chunkSize, threads, listener);
        } else {
            processor = new SequentialProcessor();
            processor.decrypt(sourcePath, destPath, password, manualOptions, chunkSize, listener);
        }
    }
}
