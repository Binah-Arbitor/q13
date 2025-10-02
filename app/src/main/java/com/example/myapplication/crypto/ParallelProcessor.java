package com.example.myapplication.crypto;

import org.bouncycastle.crypto.macs.GMac;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ParallelProcessor implements CryptoProcessor {

    private static final int MAC_SIZE_BYTES = 16; // 128 bits

    @Override
    public void encrypt(String sourcePath, String destPath, char[] password, CryptoOptions options, int chunkSize, int threads, CryptoListener listener) throws Exception {
        if (!options.getMode().isStreamMode()) {
            new SequentialProcessor().encrypt(sourcePath, destPath, password, options, chunkSize, 1, listener);
            return;
        }

        File sourceFile = new File(sourcePath);
        long fileLength = sourceFile.length();
        listener.onStart(fileLength);

        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        SecretKeySpec keySpec = KeyDerivation.deriveKey(password, salt, options.getKdf(), options.getKeyLength(), false);
        KeyParameter key = new KeyParameter(keySpec.getEncoded());

        int ivLength = options.getMode() == CryptoOptions.CipherMode.GCM ? 12 : options.getBlockSizeBits() / 8;
        byte[] iv = new byte[ivLength];
        new SecureRandom().nextBytes(iv);

        FileHeader header = new FileHeader(options, salt, iv);
        byte[] headerBytes = header.getHeaderBytes();

        try (FileOutputStream fos = new FileOutputStream(destPath)) {
            fos.write(headerBytes);
        }

        ExecutorService executor = Executors.newFixedThreadPool(threads);
        long ciphertextLength = fileLength;
        try (RandomAccessFile rafOut = new RandomAccessFile(destPath, "rw")) {
            rafOut.seek(headerBytes.length);
            rafOut.setLength(headerBytes.length + ciphertextLength + (options.getMode() == CryptoOptions.CipherMode.GCM ? MAC_SIZE_BYTES : 0));

            long offset = 0;
            while (offset < fileLength) {
                long currentChunkSize = Math.min(chunkSize, fileLength - offset);
                Runnable task = new CtrChunkTask(sourcePath, rafOut, keySpec, iv, options, offset, currentChunkSize, headerBytes.length, Cipher.ENCRYPT_MODE);
                executor.execute(task);
                offset += currentChunkSize;
            }
            executor.shutdown();
            executor.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        }

        if (options.getMode() == CryptoOptions.CipherMode.GCM) {
            byte[] tag = calculateGcmTag(destPath, key, iv, header.getAADBytes(), headerBytes.length, ciphertextLength);
            try (RandomAccessFile raf = new RandomAccessFile(destPath, "rw")) {
                raf.seek(headerBytes.length + ciphertextLength);
                raf.write(tag);
            }
        }

        listener.onProgress(fileLength, fileLength);
        listener.onSuccess("Encryption complete.", destPath);
    }

    @Override
    public void decrypt(String sourcePath, String destPath, char[] password, CryptoOptions manualOptions, int chunkSize, int threads, CryptoListener listener) throws Exception {
        File sourceFile = new File(sourcePath);
        long fileLength = sourceFile.length();

        FileHeader header = null;
        CryptoOptions options;
        byte[] salt, iv;
        long headerSize = 0;
        byte[] aad = null;

        if (manualOptions == null) {
            try (FileInputStream fis = new FileInputStream(sourceFile)) {
                header = FileHeader.fromStream(fis);
                options = header.getOptions();
                salt = header.getSalt();
                iv = header.getIv();
                headerSize = header.getHeaderSize();
                if (options.requiresAAD()) {
                    aad = header.getAADBytes();
                }
            }
        } else {
            options = manualOptions;
            salt = new byte[16]; // Dummy salt for manual mode
            iv = new byte[options.getBlockSizeBits() / 8]; // Dummy IV, manual mode for stream ciphers is not robust
        }

        if (!options.getMode().isStreamMode()) {
            new SequentialProcessor().decrypt(sourcePath, destPath, password, manualOptions, chunkSize, 1, listener);
            return;
        }

        long ciphertextLength = fileLength - headerSize - (options.getMode() == CryptoOptions.CipherMode.GCM ? MAC_SIZE_BYTES : 0);
        if (ciphertextLength < 0) throw new IOException("Invalid file size or format.");
        listener.onStart(ciphertextLength);

        SecretKeySpec keySpec = KeyDerivation.deriveKey(password, salt, options.getKdf(), options.getKeyLength(), false);

        if (options.getMode() == CryptoOptions.CipherMode.GCM) {
            KeyParameter key = new KeyParameter(keySpec.getEncoded());
            // AAD can be null for manual mode
            byte[] finalAad = (aad != null) ? aad : new byte[0];
            byte[] calculatedTag = calculateGcmTag(sourcePath, key, iv, finalAad, headerSize, ciphertextLength);
            byte[] expectedTag = new byte[MAC_SIZE_BYTES];
            try (RandomAccessFile raf = new RandomAccessFile(sourcePath, "r")) {
                raf.seek(headerSize + ciphertextLength);
                raf.readFully(expectedTag);
            }
            if (!Arrays.equals(calculatedTag, expectedTag)) {
                throw new AEADBadTagException("Authentication tag mismatch!");
            }
        }

        ExecutorService executor = Executors.newFixedThreadPool(threads);
        try (RandomAccessFile rafOut = new RandomAccessFile(destPath, "rw")) {
            rafOut.setLength(ciphertextLength);
            long offset = 0;
            while (offset < ciphertextLength) {
                long currentChunkSize = Math.min(chunkSize, ciphertextLength - offset);
                Runnable task = new CtrChunkTask(sourcePath, rafOut, keySpec, iv, options, offset, currentChunkSize, headerSize, Cipher.DECRYPT_MODE);
                executor.execute(task);
                offset += currentChunkSize;
            }
            executor.shutdown();
            executor.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        }

        listener.onProgress(ciphertextLength, ciphertextLength);
        listener.onSuccess("Decryption complete.", destPath);
    }
    
    private byte[] calculateGcmTag(String filePath, KeyParameter key, byte[] iv, byte[] aad, long ciphertextOffset, long ciphertextLength) throws IOException {
        GMac gmac = new GMac(new GCMBlockCipher(new AESEngine()));
        gmac.init(new ParametersWithIV(key, iv));
        gmac.update(aad, 0, aad.length);

        try (FileInputStream fis = new FileInputStream(filePath)) {
            fis.skip(ciphertextOffset);
            byte[] buffer = new byte[4096];
            int len;
            long remaining = ciphertextLength;
            while (remaining > 0 && (len = fis.read(buffer, 0, (int) Math.min(buffer.length, remaining))) != -1) {
                gmac.update(buffer, 0, len);
                remaining -= len;
            }
        }

        byte[] tag = new byte[gmac.getMacSize()];
        gmac.doFinal(tag, 0);
        return tag;
    }

    private static class CtrChunkTask implements Runnable {
        private final String sourcePath;
        private final RandomAccessFile rafOut;
        private final SecretKeySpec key;
        private final byte[] baseIv;
        private final CryptoOptions options;
        private final long offset;
        private final long size;
        private final long inputHeaderOffset;
        private final int mode;

        CtrChunkTask(String sourcePath, RandomAccessFile rafOut, SecretKeySpec key, byte[] iv, CryptoOptions options, long offset, long size, long inputHeaderOffset, int mode) {
            this.sourcePath = sourcePath;
            this.rafOut = rafOut;
            this.key = key;
            this.baseIv = iv;
            this.options = options;
            this.offset = offset;
            this.size = size;
            this.inputHeaderOffset = inputHeaderOffset;
            this.mode = mode;
        }

        @Override
        public void run() {
            try {
                byte[] input = new byte[(int) size];
                try (RandomAccessFile rafIn = new RandomAccessFile(sourcePath, "r")) {
                    rafIn.seek(inputHeaderOffset + offset);
                    rafIn.readFully(input);
                }

                byte[] chunkIv = CtrUtil.createCtrIvForOffset(baseIv, offset, options.getBlockSizeBits() / 8);

                Cipher cipher = Cipher.getInstance(options.getTransformation());
                cipher.init(mode, key, new IvParameterSpec(chunkIv));
                byte[] output = cipher.doFinal(input);

                synchronized (rafOut) {
                    rafOut.seek(offset);
                    rafOut.write(output);
                }
            } catch (Exception e) {
                throw new RuntimeException("Error processing chunk at offset " + offset, e);
            }
        }
    }

    private static class CtrUtil {
        public static byte[] createCtrIvForOffset(byte[] baseIv, long offset, int blockSizeBytes) {
            BigInteger ivAsInt = new BigInteger(1, baseIv);
            long blockOffset = offset / blockSizeBytes;
            BigInteger newIvAsInt = ivAsInt.add(BigInteger.valueOf(blockOffset));
            byte[] newIvBytes = newIvAsInt.toByteArray();
            byte[] finalIv = new byte[blockSizeBytes];

            if (newIvBytes.length >= blockSizeBytes) {
                System.arraycopy(newIvBytes, newIvBytes.length - blockSizeBytes, finalIv, 0, blockSizeBytes);
            } else {
                System.arraycopy(newIvBytes, 0, finalIv, blockSizeBytes - newIvBytes.length, newIvBytes.length);
            }
            return finalIv;
        }
    }
}
