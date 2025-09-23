package com.example.myapplication.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicLong;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoManager {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private CryptoListener listener;

    // Algorithm constants
    private static final String KEY_GEN_ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/CTR/NoPadding";
    private static final String CIPHER_PROVIDER = "BC";
    private static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    // Parameter constants
    private static final int KEY_LENGTH_BITS = 256;
    private static final int AES_KEY_LENGTH_BYTES = KEY_LENGTH_BITS / 8;
    private static final int HMAC_KEY_LENGTH_BYTES = 256 / 8; // SHA-256 HMAC
    private static final int DERIVED_KEY_LENGTH_BYTES = AES_KEY_LENGTH_BYTES + HMAC_KEY_LENGTH_BYTES;
    private static final int CTR_IV_LENGTH_BYTES = 16; // AES block size
    private static final int KDF_SALT_LENGTH_BYTES = 16;
    private static final int KDF_ITERATION_COUNT = 65536;
    private static final int HMAC_TAG_LENGTH_BYTES = 32; // SHA-256 output size

    // Processing constants
    private static final int CHUNK_SIZE = 16 * 1024; // 16KB
    private final int coreCount = Math.max(1, Runtime.getRuntime().availableProcessors() - 2);
    private final ExecutorService executor;

    public CryptoManager(CryptoListener listener) {
        this.listener = listener;
        this.executor = Executors.newFixedThreadPool(coreCount);
    }

    // --- Public API ---

    public void encrypt(String password, String inputFile, String outputFile) throws Exception {
        singleThreadEncrypt(password, inputFile, outputFile);
    }

    public void decrypt(String password, String inputFile, String outputFile) throws Exception {
        singleThreadDecrypt(password, inputFile, outputFile);
    }

    public void encryptMultithreaded(String password, String inputFile, String outputFile) throws Exception {
        parallelEncrypt(password, inputFile, outputFile);
    }

    public void decryptMultithreaded(String password, String inputFile, String outputFile) throws Exception {
        parallelDecrypt(password, inputFile, outputFile);
    }

    // --- Single-Threaded (Efficiency) Logic ---

    private void singleThreadEncrypt(String password, String inputPath, String outputPath) throws Exception {
        try (FileInputStream fis = new FileInputStream(inputPath); FileOutputStream fos = new FileOutputStream(outputPath)) {
            long totalSize = new File(inputPath).length();
            long processedBytes = 0;

            byte[] salt = generateRandomBytes(KDF_SALT_LENGTH_BYTES);
            byte[] iv = generateRandomBytes(CTR_IV_LENGTH_BYTES);

            SecretKeySpec aesKey = deriveKeys(password, salt, "AES");
            SecretKeySpec hmacKey = deriveKeys(password, salt, "HMAC");

            fos.write(salt);
            fos.write(iv);
            
            Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, aesKey, iv, 0); // CTR starts at block 0
            Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
            hmac.init(hmacKey);

            try (CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
                byte[] buffer = new byte[CHUNK_SIZE];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    cos.write(buffer, 0, bytesRead);
                    hmac.update(cipher.update(buffer, 0, bytesRead)); // Must update HMAC with ciphertext
                    processedBytes += bytesRead;
                    reportProgress(processedBytes, totalSize);
                }
            }
            
            byte[] hmacTag = hmac.doFinal();
            fos.write(hmacTag);

            listener.onSuccess("Encryption complete.");
        } catch (Exception e) {
            listener.onError("Encryption failed: " + e.getMessage());
            throw e;
        }
    }

    private void singleThreadDecrypt(String password, String inputPath, String outputPath) throws Exception {
        try (FileInputStream fis = new FileInputStream(inputPath); FileOutputStream fos = new FileOutputStream(outputPath)){
            
            if (new File(inputPath).length() < KDF_SALT_LENGTH_BYTES + CTR_IV_LENGTH_BYTES + HMAC_TAG_LENGTH_BYTES) {
                 throw new IllegalArgumentException("Invalid encrypted file: too short.");
            }

            byte[] salt = new byte[KDF_SALT_LENGTH_BYTES];
            fis.read(salt);
            byte[] iv = new byte[CTR_IV_LENGTH_BYTES];
            fis.read(iv);

            SecretKeySpec aesKey = deriveKeys(password, salt, "AES");
            SecretKeySpec hmacKey = deriveKeys(password, salt, "HMAC");
            
            // Verify HMAC before decryption
            verifyHmac(fis, hmacKey, inputPath);
            fis.getChannel().position(KDF_SALT_LENGTH_BYTES + CTR_IV_LENGTH_BYTES);

            Cipher cipher = initCipher(Cipher.DECRYPT_MODE, aesKey, iv, 0);
            long ciphertextLength = new File(inputPath).length() - KDF_SALT_LENGTH_BYTES - CTR_IV_LENGTH_BYTES - HMAC_TAG_LENGTH_BYTES;
            long processedBytes = 0;

            try(CipherInputStream cis = new CipherInputStream(fis, cipher)) {
                byte[] buffer = new byte[CHUNK_SIZE];
                int bytesRead;
                while ((bytesRead = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                    processedBytes += bytesRead;
                    reportProgress(processedBytes, ciphertextLength);
                }
            }
            listener.onSuccess("Decryption complete.");
        } catch (Exception e) {
            new File(outputPath).delete();
            listener.onError("Decryption failed: " + e.getMessage());
            throw e;
        }
    }
    
    // --- Parallel (Performance) Logic ---

    private void parallelEncrypt(String password, String inputPath, String outputPath) throws Exception {
        try (FileInputStream fis = new FileInputStream(inputPath); FileOutputStream fos = new FileOutputStream(outputPath)) {
            File inputFile = new File(inputPath);
            long totalSize = inputFile.length();
            long totalChunks = (totalSize + CHUNK_SIZE - 1) / CHUNK_SIZE;
            AtomicLong processedChunks = new AtomicLong(0);

            byte[] salt = generateRandomBytes(KDF_SALT_LENGTH_BYTES);
            byte[] iv = generateRandomBytes(CTR_IV_LENGTH_BYTES);

            SecretKeySpec aesKey = deriveKeys(password, salt, "AES");
            SecretKeySpec hmacKey = deriveKeys(password, salt, "HMAC");

            fos.write(salt);
            fos.write(iv);

            List<Future<byte[]>> encryptedChunks = new ArrayList<>();
            Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
            hmac.init(hmacKey);

            for (int i = 0; i < totalChunks; i++) {
                byte[] chunk = new byte[CHUNK_SIZE];
                int bytesRead = fis.read(chunk);
                if (bytesRead <= 0) break;

                byte[] actualChunk = (bytesRead == CHUNK_SIZE) ? chunk : java.util.Arrays.copyOf(chunk, bytesRead);
                
                final int chunkIndex = i;
                Callable<byte[]> task = () -> {
                    Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, aesKey, iv, chunkIndex);
                    byte[] encrypted = cipher.doFinal(actualChunk);
                    listener.onProgress((float) processedChunks.incrementAndGet() * 100 / totalChunks);
                    return encrypted;
                };
                encryptedChunks.add(executor.submit(task));
            }
            
            for (Future<byte[]> future : encryptedChunks) {
                byte[] encryptedChunk = future.get();
                fos.write(encryptedChunk);
                hmac.update(encryptedChunk);
            }

            byte[] hmacTag = hmac.doFinal();
            fos.write(hmacTag);

            listener.onSuccess("Encryption complete.");
        } catch (Exception e) {
            listener.onError("Encryption failed: " + e.getMessage());
            throw e;
        }
    }

    private void parallelDecrypt(String password, String inputPath, String outputPath) throws Exception {
        try (RandomAccessFile raf = new RandomAccessFile(inputPath, "r"); FileOutputStream fos = new FileOutputStream(outputPath)) {

            if (raf.length() < KDF_SALT_LENGTH_BYTES + CTR_IV_LENGTH_BYTES + HMAC_TAG_LENGTH_BYTES) {
                throw new IllegalArgumentException("Invalid encrypted file: too short.");
            }
            byte[] salt = new byte[KDF_SALT_LENGTH_BYTES];
            raf.readFully(salt);
            byte[] iv = new byte[CTR_IV_LENGTH_BYTES];
            raf.readFully(iv);
            
            SecretKeySpec aesKey = deriveKeys(password, salt, "AES");
            SecretKeySpec hmacKey = deriveKeys(password, salt, "HMAC");

            verifyHmac(new FileInputStream(inputPath), hmacKey, inputPath); // Verify before parallel processing

            long ciphertextLength = raf.length() - KDF_SALT_LENGTH_BYTES - CTR_IV_LENGTH_BYTES - HMAC_TAG_LENGTH_BYTES;
            long totalChunks = (ciphertextLength + CHUNK_SIZE - 1) / CHUNK_SIZE;
            AtomicLong processedChunks = new AtomicLong(0);
            List<Future<byte[]>> decryptedChunks = new ArrayList<>();

            for (int i = 0; i < totalChunks; i++) {
                long offset = (long)i * CHUNK_SIZE + KDF_SALT_LENGTH_BYTES + CTR_IV_LENGTH_BYTES;
                int length = (int) Math.min(CHUNK_SIZE, ciphertextLength - (long)i * CHUNK_SIZE);

                final int chunkIndex = i;
                Callable<byte[]> task = () -> {
                    try (RandomAccessFile innerRaf = new RandomAccessFile(inputPath, "r")) {
                        byte[] encryptedChunk = new byte[length];
                        innerRaf.seek(offset);
                        innerRaf.readFully(encryptedChunk);

                        Cipher cipher = initCipher(Cipher.DECRYPT_MODE, aesKey, iv, chunkIndex);
                        byte[] decrypted = cipher.doFinal(encryptedChunk);
                        listener.onProgress((float) processedChunks.incrementAndGet() * 100 / totalChunks);
                        return decrypted;
                    } 
                };
                decryptedChunks.add(executor.submit(task));
            }
            
            for(Future<byte[]> future : decryptedChunks) {
                fos.write(future.get());
            }

            listener.onSuccess("Decryption complete.");
        } catch (Exception e) {
            new File(outputPath).delete();
            listener.onError("Decryption failed: " + e.getMessage());
            throw e;
        }
    }
    
    // --- Helper Methods ---

    private void verifyHmac(FileInputStream fis, SecretKeySpec hmacKey, String inputPath) throws Exception {
        fis.getChannel().position(KDF_SALT_LENGTH_BYTES + CTR_IV_LENGTH_BYTES);
        Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
        hmac.init(hmacKey);

        long ciphertextLength = new File(inputPath).length() - KDF_SALT_LENGTH_BYTES - CTR_IV_LENGTH_BYTES - HMAC_TAG_LENGTH_BYTES;
        byte[] buffer = new byte[4096];
        long remaining = ciphertextLength;
        while(remaining > 0){
            int toRead = (int) Math.min(remaining, buffer.length);
            int bytesRead = fis.read(buffer, 0, toRead);
            if(bytesRead == -1) break; 
            hmac.update(buffer, 0, bytesRead);
            remaining -= bytesRead;
        }

        byte[] calculatedHmac = hmac.doFinal();

        byte[] storedHmac = new byte[HMAC_TAG_LENGTH_BYTES];
        fis.getChannel().position(KDF_SALT_LENGTH_BYTES + CTR_IV_LENGTH_BYTES + ciphertextLength);
        fis.read(storedHmac);

        if (!java.util.Arrays.equals(calculatedHmac, storedHmac)) {
            throw new SecurityException("HMAC validation failed: File tampered or corrupt.");
        }
    }

    private SecretKeySpec deriveKeys(String password, byte[] salt, String type) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGORITHM);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, KDF_ITERATION_COUNT, DERIVED_KEY_LENGTH_BYTES * 8);
        SecretKey secretKey = factory.generateSecret(spec);
        byte[] derivedKey = secretKey.getEncoded();

        if ("AES".equals(type)) {
            return new SecretKeySpec(derivedKey, 0, AES_KEY_LENGTH_BYTES, KEY_GEN_ALGORITHM);
        } else { // HMAC
            return new SecretKeySpec(derivedKey, AES_KEY_LENGTH_BYTES, HMAC_KEY_LENGTH_BYTES, HMAC_ALGORITHM);
        }
    }

    private Cipher initCipher(int mode, SecretKeySpec key, byte[] iv, long chunkIndex) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION, CIPHER_PROVIDER);
        byte[] chunkIv = iv.clone();
        long counter = chunkIndex * (CHUNK_SIZE / CTR_IV_LENGTH_BYTES);
        for (int i = 0; i < 8; i++) {
            chunkIv[CTR_IV_LENGTH_BYTES - 1 - i] ^= (byte) ((counter >> (i*8)) & 0xFF);
        }

        IvParameterSpec ivSpec = new IvParameterSpec(chunkIv);
        cipher.init(mode, key, ivSpec);
        return cipher;
    }

    private byte[] generateRandomBytes(int length) {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    private void reportProgress(long processed, long total) {
        if (listener != null && total > 0) {
            float progress = (float) processed * 100 / total;
            listener.onProgress(progress);
        }
    }
}
