package com.example.myapplication.crypto;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class ParallelProcessor implements CryptoProcessor {

    private static final int GCM_TAG_LENGTH_BYTES = 128 / 8;
    private static final int BLOCK_SIZE_BYTES = 16;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Override
    public void encrypt(String sourceFilePath, String destFilePath, char[] password, CryptoOptions options, int chunkSize, int threads, CryptoListener listener) throws Exception {
        if (!options.isParallelizable()) throw new IllegalArgumentException("Selected mode is not parallelizable: " + options.getMode());
        if (listener == null) listener = CryptoListener.DEFAULT;
        
        File sourceFile = new File(sourceFilePath);
        File destFile = new File(destFilePath);

        byte[] salt = Utils.generateRandomBytes(16);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(options.getKdf().toString(), BouncyCastleProvider.PROVIDER_NAME);
        PBEKeySpec spec = new PBEKeySpec(password, salt, 65536, options.getKeyLength());
        SecretKey secretKey = factory.generateSecret(spec);
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), options.getProtocol().name());

        byte[] iv = Utils.generateRandomBytes(options.getIvLengthBytes());
        
        long fileLength = sourceFile.length();
        long totalChunks = (fileLength + chunkSize - 1) / chunkSize;

        int headerSize;
        try (FileOutputStream fos = new FileOutputStream(destFile)) {
            FileHeader header = new FileHeader(options, salt, iv);
            headerSize = header.writeTo(fos);
        }
        try (RandomAccessFile raf = new RandomAccessFile(destFile, "rw")) {
            long finalLength = headerSize + fileLength + (options.getMode() == CryptoOptions.CipherMode.GCM ? GCM_TAG_LENGTH_BYTES : 0);
            raf.setLength(finalLength);
        }

        ExecutorService executor = Executors.newFixedThreadPool(threads);
        List<Future<Void>> futures = new ArrayList<>();

        try {
            listener.onStart(totalChunks);
            for (int i = 0; i < totalChunks; i++) {
                final long chunkIndex = i;
                Callable<Void> task = () -> {
                    long offset = chunkIndex * chunkSize;
                    int length = (int) Math.min(chunkSize, fileLength - offset);

                    byte[] plainChunk = new byte[length];
                    try (RandomAccessFile rafSource = new RandomAccessFile(sourceFile, "r")) {
                        rafSource.seek(offset);
                        rafSource.readFully(plainChunk);
                    }
                    
                    Cipher cipher;
                    byte[] encryptedData;

                    switch (options.getMode()) {
                        case GCM:
                        case CTR: 
                            cipher = Cipher.getInstance(options.getProtocol().name() + "/CTR/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
                            IvParameterSpec ctrIv = getCtrIv(iv, chunkIndex, options.getIvLengthBytes(), options.getMode() == CryptoOptions.CipherMode.GCM);
                            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ctrIv);
                            break;
                        case XTS:
                            cipher = Cipher.getInstance(options.getProtocol().name() + "/XTS/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
                            byte[] tweak = getTweakForChunk_XTS(chunkIndex, options.getBlockBitSize() / 8);
                            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(tweak));
                            break;
                        case ECB:
                             cipher = Cipher.getInstance(options.getProtocol().name() + "/ECB/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
                             cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
                            break;
                        default: throw new IllegalStateException("Non-parallelizable mode found in parallel processor: " + options.getMode());
                    }
                    encryptedData = cipher.doFinal(plainChunk);

                    try (RandomAccessFile rafDest = new RandomAccessFile(destFile, "rw")) {
                        rafDest.seek(headerSize + offset);
                        rafDest.write(encryptedData);
                    }
                    listener.onProgress(chunkIndex + 1, totalChunks);
                    return null;
                };
                futures.add(executor.submit(task));
            }

            for (Future<Void> future : futures) future.get();

            if (options.getMode() == CryptoOptions.CipherMode.GCM) {
                byte[] tag = calculateGcmTag(destFile, headerSize, fileLength, secretKeySpec, iv);
                try (RandomAccessFile raf = new RandomAccessFile(destFile, "rw")) {
                    raf.seek(headerSize + fileLength);
                    raf.write(tag);
                }
            }

            listener.onSuccess("File encrypted successfully.");

        } catch (Exception e) {
            executor.shutdownNow();
            destFile.delete();
            listener.onError("Parallel encryption failed: " + e.getMessage(), e);
            throw e;
        } finally {
            if (!executor.isShutdown()) executor.shutdown();
        }
    }

    @Override
    public void decrypt(String sourceFilePath, String destFilePath, char[] password, int chunkSize, int threads, CryptoListener listener) throws Exception {
        if (listener == null) listener = CryptoListener.DEFAULT;
        
        File sourceFile = new File(sourceFilePath);
        File destFile = new File(destFilePath);

        FileHeader header;
        int headerSize;
        try (FileInputStream fis = new FileInputStream(sourceFile)) {
            header = FileHeader.readFrom(fis);
            headerSize = (int) fis.getChannel().position();
        }
        
        CryptoOptions options = header.getOptions();
        if (!options.isParallelizable()) throw new IllegalArgumentException("File was not encrypted with a parallelizable mode: " + options.getMode());

        SecretKeyFactory factory = SecretKeyFactory.getInstance(options.getKdf().toString(), BouncyCastleProvider.PROVIDER_NAME);
        PBEKeySpec spec = new PBEKeySpec(password, header.getSalt(), 65536, options.getKeyLength());
        SecretKey secretKey = factory.generateSecret(spec);
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), options.getProtocol().name());
        byte[] iv = header.getIv();

        long contentLength = sourceFile.length() - headerSize - (options.getMode() == CryptoOptions.CipherMode.GCM ? GCM_TAG_LENGTH_BYTES : 0);
        if (contentLength < 0) throw new InvalidCipherTextException("Source file is smaller than the header and tag size.");
        
        long totalChunks = (contentLength + chunkSize - 1) / chunkSize;

        try (RandomAccessFile raf = new RandomAccessFile(destFile, "rw")) {
            raf.setLength(contentLength);
        }

        ExecutorService executor = Executors.newFixedThreadPool(threads);
        List<Future<Void>> futures = new ArrayList<>();

        try {
             if (options.getMode() == CryptoOptions.CipherMode.GCM) {
                verifyGcmTag(sourceFile, headerSize, contentLength, secretKeySpec, iv);
            }
            
            listener.onStart(totalChunks);
            for (int i = 0; i < totalChunks; i++) {
                final long chunkIndex = i;
                Callable<Void> task = () -> {
                    long offset = chunkIndex * chunkSize;
                    int length = (int) Math.min(chunkSize, contentLength - offset);

                    byte[] encryptedChunk = new byte[length];
                     try (RandomAccessFile rafSource = new RandomAccessFile(sourceFile, "r")) {
                        rafSource.seek(headerSize + offset);
                        rafSource.readFully(encryptedChunk);
                    }

                    Cipher cipher;
                    byte[] decryptedData;
                    
                     switch (options.getMode()) {
                        case GCM:
                        case CTR:
                            cipher = Cipher.getInstance(options.getProtocol().name() + "/CTR/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
                            IvParameterSpec ctrIv = getCtrIv(iv, chunkIndex, options.getIvLengthBytes(), options.getMode() == CryptoOptions.CipherMode.GCM);
                            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ctrIv);
                            break;
                        case XTS:
                             cipher = Cipher.getInstance(options.getProtocol().name() + "/XTS/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
                             byte[] tweak = getTweakForChunk_XTS(chunkIndex, options.getBlockBitSize() / 8);
                            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(tweak));
                            break;
                        case ECB:
                             cipher = Cipher.getInstance(options.getProtocol().name() + "/ECB/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
                             cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
                            break;
                        default: throw new IllegalStateException("Invalid mode for parallel decryption: " + options.getMode());
                    }
                    decryptedData = cipher.doFinal(encryptedChunk);

                    try (RandomAccessFile rafDest = new RandomAccessFile(destFile, "rw")) {
                        rafDest.seek(offset);
                        rafDest.write(decryptedData);
                    }
                    listener.onProgress(chunkIndex + 1, totalChunks);
                    return null;
                };
                futures.add(executor.submit(task));
            }

            for (Future<Void> future : futures) future.get();

            listener.onSuccess("File decrypted successfully.");

        } catch (Exception e) {
            executor.shutdownNow();
            destFile.delete();
            if (e instanceof InvalidCipherTextException) {
                listener.onError("Decryption failed: File is corrupted or password is wrong.", e);
            } else {
                listener.onError("Parallel decryption failed: " + e.getMessage(), e);
            }
            throw e;
        } finally {
            if (!executor.isShutdown()) executor.shutdown();
        }
    }

    private byte[] calculateGcmTag(File file, int headerSize, long contentLength, SecretKeySpec key, byte[] iv) throws Exception {
        GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
        gcm.init(true, new AEADParameters(new KeyParameter(key.getEncoded()), GCM_TAG_LENGTH_BYTES * 8, iv, null));

        try (FileInputStream fis = new FileInputStream(file)) {
            fis.skip(headerSize);
            byte[] buffer = new byte[8192];
            long remaining = contentLength;
            int bytesRead;
            while (remaining > 0 && (bytesRead = fis.read(buffer, 0, (int)Math.min(buffer.length, remaining))) != -1) {
                gcm.processBytes(buffer, 0, bytesRead, new byte[0], 0);
                remaining -= bytesRead;
            }
        }
        byte[] tag = new byte[GCM_TAG_LENGTH_BYTES];
        gcm.doFinal(tag, 0);
        return tag;
    }

    private void verifyGcmTag(File file, int headerSize, long contentLength, SecretKeySpec key, byte[] iv) throws Exception {
        GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
        gcm.init(false, new AEADParameters(new KeyParameter(key.getEncoded()), GCM_TAG_LENGTH_BYTES * 8, iv, null));
        
        byte[] receivedTag = new byte[GCM_TAG_LENGTH_BYTES];
        long ciphertextEnd = headerSize + contentLength;

        try (FileInputStream fis = new FileInputStream(file)) {
            fis.skip(headerSize);
            byte[] buffer = new byte[8192];
            long remaining = contentLength;
            int bytesRead;
            while (remaining > 0 && (bytesRead = fis.read(buffer, 0, (int)Math.min(buffer.length, remaining))) != -1) {
                gcm.processBytes(buffer, 0, bytesRead, new byte[0], 0);
                remaining -= bytesRead;
            }

            RandomAccessFile raf = new RandomAccessFile(file, "r");
            raf.seek(ciphertextEnd);
            raf.readFully(receivedTag);
            raf.close();
        }
        
        byte[] calculatedTag = new byte[GCM_TAG_LENGTH_BYTES];
        gcm.doFinal(calculatedTag, 0); 

        if (!java.util.Arrays.equals(calculatedTag, receivedTag)) {
            throw new InvalidCipherTextException("Tag mismatch!");
        }
    }

    private IvParameterSpec getCtrIv(byte[] initialIv, long chunkIndex, int ivLengthBytes, boolean forGcm) {
        BigInteger ivAsInt = new BigInteger(1, initialIv);
        BigInteger counter = BigInteger.valueOf(forGcm ? 2 + chunkIndex : chunkIndex);
        
        BigInteger blockOffset = BigInteger.valueOf(chunkIndex).multiply(BigInteger.valueOf(chunkSize / BLOCK_SIZE_BYTES));
        if (!forGcm) {
             counter = blockOffset;
        } else {
            // GCM counter is special. It increments the last 32 bits.
            // This is a simplified block-based increment, more robust would be a pure 128-bit add.
            counter = BigInteger.valueOf(2).add(blockOffset);
        }

        BigInteger newIvVal = ivAsInt.add(counter);
        byte[] newIvBytes = newIvVal.toByteArray();
        byte[] finalIv = new byte[ivLengthBytes];
        
        int destPos = ivLengthBytes - newIvBytes.length;
        int srcPos = Math.max(0, -destPos);
        destPos = Math.max(0, destPos);
        int len = Math.min(newIvBytes.length - srcPos, ivLengthBytes - destPos);

        System.arraycopy(newIvBytes, srcPos, finalIv, destPos, len);
        return new IvParameterSpec(finalIv);
    }

    private byte[] getTweakForChunk_XTS(long chunkIndex, int blockSizeBytes) {
        byte[] tweak = new byte[blockSizeBytes];
        // XTS uses the sector number as the tweak, which we can map from chunkIndex
        // This is a simplified mapping; a real system might use a more complex sector mapping.
        long sector = chunkIndex * (chunkSize / blockSizeBytes);
        for (int i = 0; i < blockSizeBytes; i++) {
            if (i < 8) { // A long is 8 bytes
                tweak[i] = (byte)(sector >>> (i * 8));
            } else {
                tweak[i] = 0;
            }
        }
        return tweak;
    }
}
