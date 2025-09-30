package com.example.myapplication.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.security.SecureRandom;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ParallelProcessor implements CryptoProcessor {

    @Override
    public void encrypt(String sourcePath, String destPath, char[] password, CryptoOptions options, int chunkSize, int threads, CryptoListener listener) throws Exception {
        
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        SecretKeySpec key = KeyDerivation.deriveKey(password, salt, options.getKdf(), options.getKeyLength(), options.getProtocol().isXTS());

        byte[] iv = new byte[options.getBlockSizeBits() / 8];
        new SecureRandom().nextBytes(iv);

        FileHeader header = new FileHeader(options, salt, iv);
        byte[] headerBytes = header.getHeaderBytes();

        File sourceFile = new File(sourcePath);
        long fileLength = sourceFile.length();
        listener.onStart(fileLength);

        ExecutorService executor = Executors.newFixedThreadPool(threads);
        ConcurrentLinkedQueue<Chunk> finishedChunks = new ConcurrentLinkedQueue<>();
        AtomicLong totalBytesProcessed = new AtomicLong(0);

        try (RandomAccessFile rafOut = new RandomAccessFile(destPath, "rw")) {
            rafOut.write(headerBytes);
            rafOut.setLength(fileLength + headerBytes.length);

            long offset = 0;
            int chunkIndex = 0;
            while (offset < fileLength) {
                long remaining = fileLength - offset;
                long currentChunkSize = Math.min(chunkSize, remaining);
                Chunk chunk = new Chunk(chunkIndex++, offset, currentChunkSize, sourcePath, key, iv, options);
                executor.submit(() -> {
                    try {
                        chunk.process(Cipher.ENCRYPT_MODE);
                        finishedChunks.add(chunk);
                    } catch (Exception e) {
                        listener.onError("Error processing chunk " + chunk.getIndex(), e);
                    }
                });
                offset += currentChunkSize;
            }

            executor.shutdown();

            while (!executor.isTerminated()) {
                writeFinishedChunks(rafOut, finishedChunks, totalBytesProcessed, fileLength, headerBytes.length, listener);
                Thread.sleep(100); 
            }
            writeFinishedChunks(rafOut, finishedChunks, totalBytesProcessed, fileLength, headerBytes.length, listener); // Write any remaining chunks

            listener.onSuccess("Encryption complete. Output: " + destPath);
        } catch (Exception e) {
            listener.onError("Parallel encryption failed", e);
        }
    }

    private void writeFinishedChunks(RandomAccessFile rafOut, ConcurrentLinkedQueue<Chunk> queue, AtomicLong totalBytes, long totalFileLength, int headerSize, CryptoListener listener) throws IOException {
        Chunk chunk;
        while ((chunk = queue.poll()) != null) {
            rafOut.seek(headerSize + chunk.getOffset());
            rafOut.write(chunk.getData());
            long processed = totalBytes.addAndGet(chunk.getSize());
            listener.onProgress(processed, totalFileLength);
        }
    }

    @Override
    public void decrypt(String sourcePath, String destPath, char[] password, CryptoOptions manualOptions, int chunkSize, int threads, CryptoListener listener) throws Exception {
        FileHeader header;
        CryptoOptions options;
        SecretKeySpec key;
        byte[] iv;
        long headerSize = 0;

        File sourceFile = new File(sourcePath);
        long fileLength = sourceFile.length();

        try (FileInputStream tempFis = new FileInputStream(sourceFile)) {
            if (manualOptions != null) {
                options = manualOptions;
                byte[] salt = new byte[16]; // Dummy salt
                key = KeyDerivation.deriveKey(password, salt, options.getKdf(), options.getKeyLength(), options.getProtocol().isXTS());
                iv = new byte[options.getBlockSizeBits() / 8]; // Dummy IV
            } else {
                header = FileHeader.fromStream(tempFis);
                options = header.getOptions();
                iv = header.getIv();
                key = KeyDerivation.deriveKey(password, header.getSalt(), options.getKdf(), options.getKeyLength(), options.getProtocol().isXTS());
                headerSize = header.getHeaderSize();
            }
        }

        long contentLength = fileLength - headerSize;
        listener.onStart(contentLength);

        ExecutorService executor = Executors.newFixedThreadPool(threads);
        ConcurrentLinkedQueue<Chunk> finishedChunks = new ConcurrentLinkedQueue<>();
        AtomicLong totalBytesProcessed = new AtomicLong(0);
        String tempSourcePath = sourcePath;

        try (RandomAccessFile rafOut = new RandomAccessFile(destPath, "rw")) {
            rafOut.setLength(contentLength);

            long offset = 0;
            int chunkIndex = 0;
            while (offset < contentLength) {
                long currentChunkSize = Math.min(chunkSize, contentLength - offset);
                Chunk chunk = new Chunk(chunkIndex++, offset, currentChunkSize, tempSourcePath, key, iv, options, headerSize);
                executor.submit(() -> {
                    try {
                        chunk.process(Cipher.DECRYPT_MODE);
                        finishedChunks.add(chunk);
                    } catch (Exception e) {
                        listener.onError("Error processing chunk " + chunk.getIndex(), e);
                    }
                });
                offset += currentChunkSize;
            }

            executor.shutdown();

            while (!executor.isTerminated()) {
                writeFinishedChunks(rafOut, finishedChunks, totalBytesProcessed, contentLength, 0, listener);
                Thread.sleep(100);
            }
            writeFinishedChunks(rafOut, finishedChunks, totalBytesProcessed, contentLength, 0, listener);

            listener.onSuccess("Decryption complete. Output: " + destPath);
        } catch (Exception e) {
             listener.onError("Parallel decryption failed", e);
        }
    }
}
