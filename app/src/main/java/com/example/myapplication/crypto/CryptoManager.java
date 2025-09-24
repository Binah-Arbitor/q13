package com.example.myapplication.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Handles AES-256-CTR encryption and decryption with HMAC-SHA256 authentication.
 * This class is designed for the "Simple Mode" and is not intended to be extended.
 * It supports both single-threaded and multi-threaded (parallel chunk) operations.
 *
 * File Format: [16-byte SALT] | [16-byte IV] | [ENCRYPTED DATA] | [32-byte HMAC TAG]
 */
public class CryptoManager {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final CryptoListener listener;
    private final int coreCount = Math.max(1, Runtime.getRuntime().availableProcessors() - 2);
    private final ExecutorService executor = Executors.newFixedThreadPool(coreCount);

    // --- Algorithm and Parameter Constants ---
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/CTR/NoPadding";
    private static final String MAC_ALGORITHM = "HmacSHA256";
    private static final String PROVIDER = "BC";

    private static final int SALT_LENGTH_BYTES = 16;
    private static final int IV_LENGTH_BYTES = 16; // AES block size
    private static final int KEY_LENGTH_BITS = 256;
    private static final int KDF_ITERATION_COUNT = 65536;
    private static final int MAC_TAG_LENGTH_BYTES = 32; // SHA-256 output size
    private static final int CHUNK_SIZE = 16 * 1024; // 16 KB for progress updates and parallel processing

    public CryptoManager(CryptoListener listener) {
        this.listener = listener;
    }

    // --- PUBLIC API ---

    public void encrypt(String password, InputStream inputStream, long totalSize, OutputStream outputStream, boolean multithreaded) {
        try {
            if (multithreaded) {
                parallelEncrypt(password, inputStream, outputStream);
            } else {
                singleThreadEncrypt(password, inputStream, totalSize, outputStream);
            }
            listener.onSuccess("Encryption successful.");
        } catch (Exception e) {
            listener.onError("Encryption failed: " + e.getMessage());
        }
    }

    public void decrypt(String password, InputStream inputStream, OutputStream outputStream, boolean multithreaded) {
        try {
            if (multithreaded) {
                parallelDecrypt(password, inputStream, outputStream);
            } else {
                singleThreadDecrypt(password, inputStream, outputStream);
            }
            listener.onSuccess("Decryption and verification successful.");
        } catch (Exception e) {
            listener.onError("Decryption failed: " + e.getMessage());
        }
    }

    // --- SINGLE-THREADED IMPLEMENTATIONS ---

    private void singleThreadEncrypt(String password, InputStream in, long totalSize, OutputStream out) throws Exception {
        byte[] salt = generateRandom(SALT_LENGTH_BYTES);
        byte[] iv = generateRandom(IV_LENGTH_BYTES);

        SecretKeySpec[] keys = deriveKeys(password, salt);
        SecretKeySpec encKey = keys[0];
        SecretKeySpec macKey = keys[1];

        out.write(salt);
        out.write(iv);

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION, PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, encKey, new IvParameterSpec(iv));

        Mac mac = Mac.getInstance(MAC_ALGORITHM);
        mac.init(macKey);

        byte[] buffer = new byte[CHUNK_SIZE];
        int bytesRead;
        long processedBytes = 0;

        ByteArrayOutputStream encryptedStream = new ByteArrayOutputStream();

        while ((bytesRead = in.read(buffer)) != -1) {
            byte[] encryptedBytes = cipher.update(buffer, 0, bytesRead);
            if (encryptedBytes != null) {
                encryptedStream.write(encryptedBytes);
            }
            processedBytes += bytesRead;
            reportProgress(processedBytes, totalSize);
        }
        byte[] finalEncrypted = cipher.doFinal();
        if (finalEncrypted != null) {
            encryptedStream.write(finalEncrypted);
        }

        byte[] ciphertext = encryptedStream.toByteArray();
        mac.update(ciphertext);
        byte[] hmacTag = mac.doFinal();

        out.write(ciphertext);
        out.write(hmacTag);
    }

    private void singleThreadDecrypt(String password, InputStream in, OutputStream out) throws Exception {
        byte[] salt = readBytes(in, SALT_LENGTH_BYTES);
        byte[] iv = readBytes(in, IV_LENGTH_BYTES);

        SecretKeySpec[] keys = deriveKeys(password, salt);
        SecretKeySpec encKey = keys[0];
        SecretKeySpec macKey = keys[1];

        ByteArrayOutputStream memStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[CHUNK_SIZE];
        int bytesRead;
        while ((bytesRead = in.read(buffer)) != -1) {
            memStream.write(buffer, 0, bytesRead);
        }
        byte[] ciphertextAndMac = memStream.toByteArray();

        verifyAndDecrypt(encKey, macKey, iv, ciphertextAndMac, out, true);
    }

    // --- PARALLEL IMPLEMENTATIONS ---

    private void parallelEncrypt(String password, InputStream in, OutputStream out) throws Exception {
        byte[] salt = generateRandom(SALT_LENGTH_BYTES);
        byte[] iv = generateRandom(IV_LENGTH_BYTES);

        SecretKeySpec[] keys = deriveKeys(password, salt);
        SecretKeySpec encKey = keys[0];
        SecretKeySpec macKey = keys[1];

        out.write(salt);
        out.write(iv);

        ByteArrayOutputStream plaintextStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[CHUNK_SIZE];
        int bytesRead;
        while ((bytesRead = in.read(buffer)) != -1) {
            plaintextStream.write(buffer, 0, bytesRead);
        }
        byte[] plaintext = plaintextStream.toByteArray();

        List<Future<byte[]>> encryptedChunks = new ArrayList<>();
        int chunkCount = (int) Math.ceil((double) plaintext.length / CHUNK_SIZE);

        for (int i = 0; i < chunkCount; i++) {
            int offset = i * CHUNK_SIZE;
            int length = Math.min(CHUNK_SIZE, plaintext.length - offset);
            byte[] chunk = Arrays.copyOfRange(plaintext, offset, offset + length);
            final long blockOffset = (long) i * (CHUNK_SIZE / 16);

            encryptedChunks.add(executor.submit(() -> {
                Cipher chunkCipher = Cipher.getInstance(CIPHER_TRANSFORMATION, PROVIDER);
                chunkCipher.init(Cipher.ENCRYPT_MODE, encKey, createIvSpecForChunk(iv, blockOffset));
                return chunkCipher.doFinal(chunk);
            }));
            reportProgress((long)(i + 1) * CHUNK_SIZE, plaintext.length);
        }

        ByteArrayOutputStream ciphertextStream = new ByteArrayOutputStream();
        for (Future<byte[]> chunkFuture : encryptedChunks) {
            ciphertextStream.write(chunkFuture.get());
        }
        byte[] ciphertext = ciphertextStream.toByteArray();

        Mac mac = Mac.getInstance(MAC_ALGORITHM);
        mac.init(macKey);
        mac.update(ciphertext);
        byte[] hmacTag = mac.doFinal();

        out.write(ciphertext);
        out.write(hmacTag);
    }

    private void parallelDecrypt(String password, InputStream in, OutputStream out) throws Exception {
        byte[] salt = readBytes(in, SALT_LENGTH_BYTES);
        byte[] iv = readBytes(in, IV_LENGTH_BYTES);

        SecretKeySpec[] keys = deriveKeys(password, salt);
        SecretKeySpec encKey = keys[0];
        SecretKeySpec macKey = keys[1];

        ByteArrayOutputStream memStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[CHUNK_SIZE];
        int bytesRead;
        while ((bytesRead = in.read(buffer)) != -1) {
            memStream.write(buffer, 0, bytesRead);
        }
        byte[] ciphertextAndMac = memStream.toByteArray();

        byte[] ciphertext = verifyAndGetCiphertext(macKey, ciphertextAndMac);

        List<Future<byte[]>> decryptedChunks = new ArrayList<>();
        int chunkCount = (int) Math.ceil((double) ciphertext.length / CHUNK_SIZE);

        for (int i = 0; i < chunkCount; i++) {
            int offset = i * CHUNK_SIZE;
            int length = Math.min(CHUNK_SIZE, ciphertext.length - offset);
            byte[] chunk = Arrays.copyOfRange(ciphertext, offset, offset + length);
            final long blockOffset = (long) i * (CHUNK_SIZE / 16);

            decryptedChunks.add(executor.submit(() -> {
                Cipher chunkCipher = Cipher.getInstance(CIPHER_TRANSFORMATION, PROVIDER);
                chunkCipher.init(Cipher.DECRYPT_MODE, encKey, createIvSpecForChunk(iv, blockOffset));
                return chunkCipher.doFinal(chunk);
            }));
            reportProgress((long)(i + 1) * CHUNK_SIZE, ciphertext.length);
        }

        for (Future<byte[]> chunkFuture : decryptedChunks) {
            out.write(chunkFuture.get());
        }
    }

    // --- HELPER METHODS ---

    private void verifyAndDecrypt(SecretKeySpec encKey, SecretKeySpec macKey, byte[] iv, byte[] ciphertextAndMac, OutputStream out, boolean report) throws Exception {
        byte[] ciphertext = verifyAndGetCiphertext(macKey, ciphertextAndMac);

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION, PROVIDER);
        cipher.init(Cipher.DECRYPT_MODE, encKey, new IvParameterSpec(iv));

        ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(ciphertext);
        byte[] buffer = new byte[CHUNK_SIZE];
        int bytesRead;
        long processedBytes = 0;
        while ((bytesRead = ciphertextIn.read(buffer)) != -1) {
            byte[] decryptedBytes = cipher.update(buffer, 0, bytesRead);
            if (decryptedBytes != null) {
                out.write(decryptedBytes);
            }
            if(report) {
                processedBytes += bytesRead;
                reportProgress(processedBytes, ciphertext.length);
            }
        }
        byte[] finalDecrypted = cipher.doFinal();
        if (finalDecrypted != null) {
            out.write(finalDecrypted);
        }
    }

    private byte[] verifyAndGetCiphertext(SecretKeySpec macKey, byte[] data) throws Exception {
        if (data.length < MAC_TAG_LENGTH_BYTES) {
            throw new SecurityException("Invalid data: too short to contain HMAC tag.");
        }

        byte[] ciphertext = Arrays.copyOfRange(data, 0, data.length - MAC_TAG_LENGTH_BYTES);
        byte[] storedMac = Arrays.copyOfRange(data, ciphertext.length, data.length);

        Mac mac = Mac.getInstance(MAC_ALGORITHM);
        mac.init(macKey);
        mac.update(ciphertext);
        byte[] calculatedMac = mac.doFinal();

        if (!Arrays.equals(storedMac, calculatedMac)) {
            throw new SecurityException("HMAC validation failed: File is corrupt or has been tampered with.");
        }
        return ciphertext;
    }

    private SecretKeySpec[] deriveKeys(String password, byte[] salt) throws Exception {
        int derivedKeyLength = (KEY_LENGTH_BITS * 2) / 8; // for AES key and MAC key
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, KDF_ITERATION_COUNT, derivedKeyLength * 8);
        byte[] derivedKeyBytes = factory.generateSecret(spec).getEncoded();

        SecretKeySpec encKey = new SecretKeySpec(derivedKeyBytes, 0, KEY_LENGTH_BITS / 8, ENCRYPTION_ALGORITHM);
        SecretKeySpec macKey = new SecretKeySpec(derivedKeyBytes, KEY_LENGTH_BITS / 8, KEY_LENGTH_BITS / 8, MAC_ALGORITHM);
        return new SecretKeySpec[]{encKey, macKey};
    }

    private IvParameterSpec createIvSpecForChunk(byte[] baseIv, long blockOffset) {
        byte[] counterIv = baseIv.clone();
        for (int i = 0; i < 8; i++) { // Assumes little-endian byte order for counter
            counterIv[IV_LENGTH_BYTES - 1 - i] += (byte) ((blockOffset >> (i * 8)) & 0xFF);
        }
        return new IvParameterSpec(counterIv);
    }

    private byte[] generateRandom(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private byte[] readBytes(InputStream in, int length) throws Exception {
        byte[] bytes = new byte[length];
        int bytesRead = in.read(bytes);
        if (bytesRead != length) {
            throw new Exception("Could not read required bytes from stream (salt/iv). Read: "+ bytesRead + ", Expected: " + length);
        }
        return bytes;
    }

    private void reportProgress(long processed, long total) {
        if (listener != null && total > 0) {
            int progress = (int) Math.min(100, (processed * 100) / total);
            listener.onProgress(progress);
        }
    }
}