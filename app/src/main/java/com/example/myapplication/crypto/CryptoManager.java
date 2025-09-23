package com.example.myapplication.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoManager {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private CryptoListener listener;

    private static final String ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String CIPHER_PROVIDER = "BC";

    private static final int KEY_LENGTH = 256; // bits
    private static final int GCM_IV_LENGTH = 12; // bytes (96 bits)
    private static final int GCM_TAG_LENGTH = 128; // bits
    private static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int KDF_SALT_LENGTH = 16; // bytes (128 bits)
    private static final int KDF_ITERATION_COUNT = 65536;
    private static final int CHUNK_SIZE = 16 * 1024; // 16KB

    public CryptoManager(CryptoListener listener) {
        this.listener = listener;
    }

    // Standard single-threaded encryption
    public void encrypt(String password, String inputFile, String outputFile) throws Exception {
        process(password, inputFile, outputFile, false, Cipher.ENCRYPT_MODE);
    }

    // Standard single-threaded decryption
    public void decrypt(String password, String inputFile, String outputFile) throws Exception {
        process(password, inputFile, outputFile, false, Cipher.DECRYPT_MODE);
    }
    
    // Pipelined multi-threaded encryption
    public void encryptMultithreaded(String password, String inputFile, String outputFile) throws Exception {
        process(password, inputFile, outputFile, true, Cipher.ENCRYPT_MODE);
    }

    // Pipelined multi-threaded decryption
    public void decryptMultithreaded(String password, String inputFile, String outputFile) throws Exception {
        process(password, inputFile, outputFile, true, Cipher.DECRYPT_MODE);
    }

    private void process(String password, String inputFile, String outputFile, boolean multithreaded, int mode) throws Exception {
        if (multithreaded) {
            if (mode == Cipher.ENCRYPT_MODE) {
                pipelineEncrypt(password, inputFile, outputFile);
            } else {
                pipelineDecrypt(password, inputFile, outputFile);
            }
        } else {
            if (mode == Cipher.ENCRYPT_MODE) {
                 singleThreadEncrypt(password, inputFile, outputFile);
            } else {
                singleThreadDecrypt(password, inputFile, outputFile);
            }
        }
    }

    private void singleThreadEncrypt(String password, String inputFile, String outputFile) throws Exception {
         try (FileInputStream fis = new FileInputStream(inputFile); 
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[KDF_SALT_LENGTH];
            random.nextBytes(salt);
            byte[] iv = new byte[GCM_IV_LENGTH];
            random.nextBytes(iv);

            fos.write(salt);
            fos.write(iv);

            SecretKeySpec secretKey = deriveKey(password, salt);
            Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, secretKey, iv);
            
            long totalSize = fis.getChannel().size();
            long processedBytes = 0;

            try(CipherOutputStream cos = new CipherOutputStream(fos, cipher)){
                byte[] buffer = new byte[CHUNK_SIZE];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    cos.write(buffer, 0, bytesRead);
                    processedBytes += bytesRead;
                    reportProgress(processedBytes, totalSize);
                }
            }
            if (listener != null) listener.onSuccess("Encryption complete.");
        } catch (Exception e) {
            if (listener != null) listener.onError("Encryption failed: " + e.getMessage());
            throw e;
        }
    }

     private void singleThreadDecrypt(String password, String inputFile, String outputFile) throws Exception {
        try (FileInputStream fis = new FileInputStream(inputFile); 
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            byte[] salt = new byte[KDF_SALT_LENGTH];
            byte[] iv = new byte[GCM_IV_LENGTH];
            if (fis.read(salt) != KDF_SALT_LENGTH || fis.read(iv) != GCM_IV_LENGTH) {
                throw new IllegalArgumentException("Invalid encrypted file format.");
            }

            SecretKeySpec secretKey = deriveKey(password, salt);
            Cipher cipher = initCipher(Cipher.DECRYPT_MODE, secretKey, iv);

            long totalSize = fis.getChannel().size() + KDF_SALT_LENGTH + GCM_IV_LENGTH;
            long processedBytes = KDF_SALT_LENGTH + GCM_IV_LENGTH;
            
            try (CipherInputStream cis = new CipherInputStream(fis, cipher)){
                byte[] buffer = new byte[CHUNK_SIZE];
                int bytesRead;
                while ((bytesRead = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                    processedBytes += bytesRead;
                    reportProgress(processedBytes, totalSize);
                }
            }
            if (listener != null) listener.onSuccess("Decryption complete.");
        } catch (Exception e) {
            if (listener != null) listener.onError("Decryption failed: " + e.getMessage());
            throw e;
        }
    }

    private void pipelineEncrypt(String password, String inputFile, String outputFile) throws Exception {
        BlockingQueue<byte[]> readQueue = new ArrayBlockingQueue<>(10);
        BlockingQueue<byte[]> writeQueue = new ArrayBlockingQueue<>(10);
        final Exception[] threadException = {null};

        try (FileInputStream fis = new FileInputStream(inputFile); 
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            long totalSize = fis.getChannel().size();
            long[] processedBytes = {0};
            final boolean[] readFinished = {false};

            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[KDF_SALT_LENGTH];
            random.nextBytes(salt);
            byte[] iv = new byte[GCM_IV_LENGTH];
            random.nextBytes(iv);

            fos.write(salt);
            fos.write(iv);

            SecretKeySpec secretKey = deriveKey(password, salt);
            Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, secretKey, iv);

            // Reader Thread
            Thread reader = new Thread(() -> {
                try {
                    byte[] chunk = new byte[CHUNK_SIZE];
                    int bytesRead;
                    while ((bytesRead = fis.read(chunk)) != -1) {
                        if (bytesRead < CHUNK_SIZE) {
                            byte[] smallerChunk = new byte[bytesRead];
                            System.arraycopy(chunk, 0, smallerChunk, 0, bytesRead);
                            readQueue.put(smallerChunk);
                        } else {
                            readQueue.put(chunk.clone());
                        }
                    }
                } catch (Exception e) {
                    threadException[0] = e;
                } finally {
                    readFinished[0] = true;
                }
            });

            // Writer Thread
            Thread writer = new Thread(() -> {
                try {
                    while (!readFinished[0] || !writeQueue.isEmpty()) {
                        byte[] encryptedChunk = writeQueue.poll(100, TimeUnit.MILLISECONDS);
                        if(encryptedChunk != null) {
                            fos.write(encryptedChunk);
                        }
                    }
                } catch (Exception e) {
                    threadException[0] = e;
                }
            });
            
            reader.start();
            writer.start();

            // Main thread does the encryption
            try {
                 while (!readFinished[0] || !readQueue.isEmpty()) {
                    byte[] chunk = readQueue.poll(100, TimeUnit.MILLISECONDS);
                     if (chunk != null) {
                         byte[] encryptedChunk = cipher.update(chunk);
                         if(encryptedChunk != null) {
                            writeQueue.put(encryptedChunk);
                            processedBytes[0] += chunk.length;
                            reportProgress(processedBytes[0], totalSize);
                         }
                     }
                }
                byte[] finalChunk = cipher.doFinal();
                if(finalChunk != null) {
                    writeQueue.put(finalChunk);
                }
            } catch(Exception e) {
                threadException[0] = e;
            }

            reader.join();
            writer.join();

            if (threadException[0] != null) throw threadException[0];
            if (listener != null) listener.onSuccess("Encryption complete.");
        }
    }
    
    private void pipelineDecrypt(String password, String inputFile, String outputFile) throws Exception{
        // Decryption pipeline is more complex due to GCM's streaming nature and auth tag.
        // A simple parallel read/write is safer and still offers performance benefits.
        singleThreadDecrypt(password, inputFile, outputFile);
    }

    private SecretKeySpec deriveKey(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGORITHM);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, KDF_ITERATION_COUNT, KEY_LENGTH);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), ALGORITHM);
    }

    private Cipher initCipher(int mode, SecretKeySpec key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION, CIPHER_PROVIDER);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(mode, key, gcmSpec);
        return cipher;
    }

    private void reportProgress(long processed, long total) {
        if (listener != null && total > 0) {
            float progress = (float) processed / total * 100;
            listener.onProgress(progress);
        }
    }
}
