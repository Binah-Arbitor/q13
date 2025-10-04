package com.example.myapplication.crypto;

public class CryptoManager {

    public void encrypt(String sourcePath, String destPath, char[] password, CryptoOptions options, int chunkSize, int threadCount, CryptoListener listener) throws Exception {
        IProcessor processor = getProcessor(threadCount);
        processor.encrypt(sourcePath, destPath, password, options, chunkSize, listener);
    }

    public void decrypt(String sourcePath, String destPath, char[] password, CryptoOptions manualOptions, int chunkSize, int threadCount, CryptoListener listener) throws Exception {
        // Decryption is always sequential for now to ensure correctness
        IProcessor processor = new SequentialProcessor(); 
        processor.decrypt(sourcePath, destPath, password, manualOptions, chunkSize, listener);
    }

    private IProcessor getProcessor(int threadCount) {
        if (threadCount > 1) {
            return new ParallelProcessor(threadCount);
        } else {
            return new SequentialProcessor();
        }
    }
}
