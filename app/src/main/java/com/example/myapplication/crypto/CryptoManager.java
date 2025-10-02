package com.example.myapplication.crypto;

import java.io.File;
import java.io.FileInputStream;

public class CryptoManager {

    public void encrypt(String sourcePath, String destPath, char[] password, CryptoOptions options, int chunkSize, int threads, CryptoListener listener) throws Exception {
        File sourceFile = new File(sourcePath);
        long fileLength = sourceFile.length();

        // Adjust chunk size if the file is smaller than the chunk size
        if (fileLength < chunkSize) {
            chunkSize = (int) fileLength;
        }
        // Ensure chunk size is not zero for empty files
        if (chunkSize <= 0) {
            chunkSize = 1024; // Or some other default minimum
        }

        CryptoProcessor processor;
        if (threads > 1 && options.getMode().isStreamMode()) {
            processor = new ParallelProcessor();
            processor.encrypt(sourcePath, destPath, password, options, chunkSize, threads, listener);
        } else {
            processor = new SequentialProcessor();
            processor.encrypt(sourcePath, destPath, password, options, chunkSize, 1, listener);
        }
    }

    public void decrypt(String sourcePath, String destPath, char[] password, CryptoOptions manualOptions, int chunkSize, int threads, CryptoListener listener) throws Exception {
        File sourceFile = new File(sourcePath);
        long fileLength = sourceFile.length();
        long dataLength = fileLength;

        // In automatic mode, subtract header size to get the actual data length
        if (manualOptions == null) {
            try (FileInputStream fis = new FileInputStream(sourceFile)) {
                FileHeader header = FileHeader.fromStream(fis);
                dataLength = fileLength - header.getHeaderSize();
            } catch (Exception e) {
                // If header reading fails, proceed with fileLength, but log it.
                System.err.println("Could not read header to determine data length: " + e.getMessage());
            }
        }

        // Adjust chunk size if the data is smaller than the chunk size
        if (dataLength < chunkSize) {
            chunkSize = (int) dataLength;
        }
        // Ensure chunk size is not zero for empty files or very small files
        if (chunkSize <= 0) {
            chunkSize = 1024; // Or some other default minimum
        }

        CryptoProcessor processor;
        boolean canParallel = threads > 1 && (manualOptions != null ? manualOptions.getMode().isStreamMode() : isEncryptedFileStreamable(sourcePath));

        if (canParallel) {
            processor = new ParallelProcessor();
            processor.decrypt(sourcePath, destPath, password, manualOptions, chunkSize, threads, listener);
        } else {
            processor = new SequentialProcessor();
            processor.decrypt(sourcePath, destPath, password, manualOptions, chunkSize, 1, listener);
        }
    }

    private boolean isEncryptedFileStreamable(String sourcePath) {
        try (FileInputStream fis = new FileInputStream(sourcePath)) {
            FileHeader header = FileHeader.fromStream(fis);
            return header.getOptions().getMode().isStreamMode();
        } catch (Exception e) {
            return false;
        }
    }
}
