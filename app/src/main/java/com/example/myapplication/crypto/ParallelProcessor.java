package com.example.myapplication.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class ParallelProcessor implements CryptoProcessor {

    private static final int BLOCK_SIZE_BYTES = 16; // AES block size

    @Override
    public void encrypt(String sourceFilePath, String destFilePath, char[] password, CryptoOptions options, int chunkSize, int threads, CryptoListener listener) throws Exception {
        FileHeader header = new FileHeader(options);
        byte[] salt = Utils.generateRandomBytes(16);
        header.setSalt(salt);

        SecretKeySpec key = KeyDerivation.deriveKey(password, salt, options.getKdf(), options.getKeyLength(), options.getProtocol().isXTS());

        byte[] iv = Utils.generateRandomBytes(options.getIvLengthBytes());
        header.setIv(iv);

        ExecutorService executor = Executors.newFixedThreadPool(threads + 2); // +2 for reader and writer
        BlockingQueue<Chunk> readQueue = new ArrayBlockingQueue<>(threads);
        BlockingQueue<Chunk> writeQueue = new ArrayBlockingQueue<>(threads);

        File sourceFile = new File(sourceFilePath);
        long totalSize = sourceFile.length();
        listener.onStart(totalSize);

        AtomicLong progress = new AtomicLong(0);

        // Reader Thread
        executor.submit(() -> {
            try (FileInputStream fis = new FileInputStream(sourceFile)) {
                long offset = 0;
                int chunkIndex = 0;
                while (offset < totalSize) {
                    int size = (int) Math.min(chunkSize, totalSize - offset);
                    byte[] data = new byte[size];
                    fis.read(data);
                    readQueue.put(new Chunk(chunkIndex++, data, size));
                    offset += size;
                }
                readQueue.put(new Chunk(-1, null, 0)); // Poison pill
            } catch (Exception e) {
                listener.onError("Error reading file", e);
            }
        });

        // Worker Threads
        for (int i = 0; i < threads; i++) {
            executor.submit(() -> {
                try {
                    while (true) {
                        Chunk chunk = readQueue.take();
                        if (chunk.isPoisonPill()) {
                            readQueue.put(chunk); // Put it back for other workers
                            break;
                        }
                        chunk.setData(processChunk(chunk.getData(), chunk.getIndex(), key, iv, options, chunkSize));
                        writeQueue.put(chunk);
                    }
                } catch (Exception e) {
                    listener.onError("Error during encryption worker task", e);
                }
            });
        }

        // Writer Thread
        try (FileOutputStream fos = new FileOutputStream(destFilePath)) {
            fos.write(header.getHeaderBytes());
            long chunksToWrite = (long) Math.ceil((double) totalSize / chunkSize);
            for (int i = 0; i < chunksToWrite; i++) {
                Chunk chunk = writeQueue.take();
                fos.write(chunk.getData());
                long currentProgress = progress.addAndGet(chunk.getSize());
                listener.onProgress(currentProgress, totalSize);
            }
            listener.onSuccess("Encryption completed successfully.");
        } finally {
            executor.shutdownNow();
        }
    }

    @Override
    public void decrypt(String sourceFilePath, String destFilePath, char[] password, CryptoOptions manualOptions, int chunkSize, int threads, CryptoListener listener) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(threads + 2);
        BlockingQueue<Chunk> readQueue = new ArrayBlockingQueue<>(threads);
        BlockingQueue<Chunk> writeQueue = new ArrayBlockingQueue<>(threads);

        File sourceFile = new File(sourceFilePath);
        long totalSize = sourceFile.length();

        CryptoOptions options;
        SecretKeySpec key;
        byte[] iv;
        long headerSize;

        if (manualOptions != null) {
            options = manualOptions;
            // In manual mode, we must assume a salt/IV or derive them differently. For now, a placeholder:
            byte[] salt = new byte[16]; // Or derive from password in a pre-defined way
            iv = new byte[options.getIvLengthBytes()];
            key = KeyDerivation.deriveKey(password, salt, options.getKdf(), options.getKeyLength(), options.getProtocol().isXTS());
            headerSize = 0;
        } else {
            try (FileInputStream tempFis = new FileInputStream(sourceFile)) {
                FileHeader header = FileHeader.fromStream(tempFis);
                options = header.getOptions();
                iv = header.getIv();
                key = KeyDerivation.deriveKey(password, header.getSalt(), options.getKdf(), options.getKeyLength(), options.getProtocol().isXTS());
                headerSize = FileHeader.HEADER_SIZE;
            }
        }

        long contentSize = totalSize - headerSize;
        listener.onStart(contentSize);
        AtomicLong progress = new AtomicLong(0);

        // Reader Thread
        executor.submit(() -> {
            try (RandomAccessFile raf = new RandomAccessFile(sourceFile, "r")) {
                raf.seek(headerSize);
                long offset = 0;
                int chunkIndex = 0;
                while (offset < contentSize) {
                    int size = (int) Math.min(chunkSize, contentSize - offset);
                    byte[] data = new byte[size];
                    raf.read(data, 0, size);
                    readQueue.put(new Chunk(chunkIndex++, data, size));
                    offset += size;
                }
                readQueue.put(new Chunk(-1, null, 0)); // Poison pill
            } catch (Exception e) {
                listener.onError("Error reading encrypted file", e);
            }
        });

        // Worker Threads
        for (int i = 0; i < threads; i++) {
            executor.submit(() -> {
                try {
                    while (true) {
                        Chunk chunk = readQueue.take();
                        if (chunk.isPoisonPill()) {
                            readQueue.put(chunk);
                            break;
                        }
                        chunk.setData(processChunk(chunk.getData(), chunk.getIndex(), key, iv, options, chunkSize));
                        writeQueue.put(chunk);
                    }
                } catch (Exception e) {
                    listener.onError("Error during decryption worker task", e);
                }
            });
        }

        // Writer Thread
        try (FileOutputStream fos = new FileOutputStream(destFilePath)) {
            long chunksToWrite = (long) Math.ceil((double) contentSize / chunkSize);
            for (int i = 0; i < chunksToWrite; i++) {
                Chunk chunk = writeQueue.take();
                fos.write(chunk.getData());
                long currentProgress = progress.addAndGet(chunk.getSize());
                listener.onProgress(currentProgress, contentSize);
            }
            listener.onSuccess("Decryption completed successfully.");
        } finally {
            executor.shutdownNow();
        }
    }

    private byte[] processChunk(byte[] data, int chunkIndex, SecretKeySpec key, byte[] iv, CryptoOptions options, int chunkSize) throws Exception {
        // For stream ciphers like CTR, the IV needs to be updated for each block.
        // This is a simplified approach; a robust implementation needs careful IV management per block.
        Cipher cipher = options.getProtocol().getInitialisedCipher(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv)); // Re-init is important for some modes

        if (options.getMode() == CryptoOptions.CipherMode.CTR) {
            BigInteger ivInt = new BigInteger(1, iv);
            BigInteger blockOffset = BigInteger.valueOf(chunkIndex).multiply(BigInteger.valueOf(chunkSize / BLOCK_SIZE_BYTES));
            ivInt = ivInt.add(blockOffset);
            IvParameterSpec ivSpec = new IvParameterSpec(ivInt.toByteArray());
            cipher.init(options.getProtocol() == CryptoOptions.CryptoProtocol.AES ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key, ivSpec);
        }
        
        return cipher.doFinal(data);
    }


    private static class Chunk {
        private final int index;
        private byte[] data;
        private final int size;

        Chunk(int index, byte[] data, int size) {
            this.index = index;
            this.data = data;
            this.size = size;
        }

        boolean isPoisonPill() {
            return index == -1;
        }

        int getIndex() {
            return index;
        }

        byte[] getData() {
            return data;
        }

        int getSize() {
            return size;
        }

        void setData(byte[] data) {
            this.data = data;
        }
    }
}
