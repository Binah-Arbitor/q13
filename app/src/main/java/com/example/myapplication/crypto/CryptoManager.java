
package com.example.myapplication.crypto;

import android.content.Context;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class CryptoManager {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final CryptoListener listener;
    private final Context context;

    // --- Algorithm and Parameter Constants (for SIMPLE mode) ---
    private static final String SIMPLE_KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String SIMPLE_ENCRYPTION_ALGORITHM = "AES";
    private static final String SIMPLE_CIPHER_TRANSFORMATION = "AES/CTR/NoPadding";
    private static final String MAC_ALGORITHM = "HmacSHA256"; // Common for both
    private static final String PROVIDER = "BC"; // Common for both

    private static final int SALT_LENGTH_BYTES = 16;
    private static final int IV_LENGTH_BYTES = 16; // AES block size
    private static final int SIMPLE_KEY_LENGTH_BITS = 256;
    private static final int SIMPLE_KDF_ITERATION_COUNT = 65536;
    private static final int MAC_TAG_LENGTH_BYTES = 32; // SHA-256 output size
    private static final int SIMPLE_CHUNK_SIZE = 64 * 1024; // 64 KB

    public CryptoManager(CryptoListener listener, Context context) {
        this.listener = listener;
        this.context = context;
    }

    // --- PUBLIC API ---

    public void encrypt(String password, InputStream inputStream, long totalSize, OutputStream outputStream, boolean multithreaded) {
        new Thread(() -> {
            try {
                streamEncrypt(password, inputStream, totalSize, outputStream);
                listener.onSuccess("Encryption successful.");
            } catch (Exception e) {
                e.printStackTrace();
                listener.onError("Encryption failed: " + e.getMessage());
            }
        }).start();
    }

    public void decrypt(String password, InputStream inputStream, long totalSize, OutputStream outputStream, boolean multithreaded) {
        new Thread(() -> {
            try {
                streamDecrypt(password, inputStream, totalSize, outputStream);
                listener.onSuccess("Decryption and verification successful.");
            } catch (Exception e) {
                e.printStackTrace();
                listener.onError("Decryption failed: " + e.getMessage());
            }
        }).start();
    }
    
    public void encryptAdvanced(String password, InputStream inputStream, long totalSize, OutputStream outputStream, CryptoOptions options) {
        new Thread(() -> {
            try {
                streamEncryptAdvanced(password, inputStream, totalSize, outputStream, options);
                listener.onSuccess("Advanced encryption successful.");
            } catch (Exception e) {
                e.printStackTrace();
                listener.onError("Advanced encryption failed: " + e.getMessage());
            }
        }).start();
    }

    // --- ADVANCED ENCRYPTION IMPLEMENTATION ---
    private void streamEncryptAdvanced(String password, InputStream in, long totalSize, OutputStream out, CryptoOptions options) throws Exception {
        File tempEncryptedFile = null;
        try {
            // 1. Derive keys from password using advanced options
            byte[] salt = generateRandom(SALT_LENGTH_BYTES);
            SecretKeySpec[] keys = deriveKeysAdvanced(password, salt, options);
            SecretKeySpec encKey = keys[0];
            SecretKeySpec macKey = keys[1];

            // 2. Generate IV
            byte[] iv = generateRandom(IV_LENGTH_BYTES);

            // 3. Write Salt and IV to the final output stream
            out.write(salt);
            out.write(iv);
            listener.onLog("Salt and IV written.");

            // 4. Encrypt data to a temporary file
            listener.onLog("Encrypting data to temporary file...");
            tempEncryptedFile = File.createTempFile("enc_adv", ".tmp", context.getCacheDir());
            try (FileOutputStream tempOut = new FileOutputStream(tempEncryptedFile)) {
                Cipher cipher = Cipher.getInstance(options.getCipherTransformation(), PROVIDER);
                cipher.init(Cipher.ENCRYPT_MODE, encKey, new IvParameterSpec(iv));

                byte[] buffer = new byte[options.getChunkSize()];
                int bytesRead;
                long processedBytes = 0;

                while ((bytesRead = in.read(buffer)) != -1) {
                    byte[] encryptedBytes = cipher.update(buffer, 0, bytesRead);
                    if (encryptedBytes != null) {
                        tempOut.write(encryptedBytes);
                    }
                    processedBytes += bytesRead;
                    reportProgress(processedBytes, totalSize);
                }
                byte[] finalBytes = cipher.doFinal();
                if (finalBytes != null) {
                    tempOut.write(finalBytes);
                }
            }
            listener.onLog("Temporary file encryption complete.");

            // 5. Calculate HMAC of the encrypted temporary file
            listener.onLog("Calculating HMAC tag...");
            byte[] hmacTag = calculateHmac(macKey, tempEncryptedFile);
            listener.onLog("HMAC tag calculated.");

            // 6. Stream the encrypted data from temp file to the final output stream
            try (FileInputStream tempIn = new FileInputStream(tempEncryptedFile)) {
                byte[] buffer = new byte[options.getChunkSize()];
                int bytesRead;
                while ((bytesRead = tempIn.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }

            // 7. Write HMAC tag to the final output stream
            out.write(hmacTag);
            listener.onLog("Encrypted data and HMAC tag written to final output.");

        } finally {
            if (tempEncryptedFile != null && tempEncryptedFile.exists()) {
                tempEncryptedFile.delete();
            }
        }
    }

    private SecretKeySpec[] deriveKeysAdvanced(String password, byte[] salt, CryptoOptions options) throws Exception {
        listener.onLog("Deriving keys with " + options.getKdf() + ", " + options.getKeyLength() + "-bit key...");
        // We derive one key of (KeyLength + MAC_Key_Length) and split it.
        // We use a fixed SHA-256 for HMAC, so MAC key is always 256 bits.
        int macKeyLengthBits = 256;
        int derivedKeyLength = options.getKeyLength() + macKeyLengthBits;
        
        // Note: Iteration count is still hardcoded for security consistency.
        // Making this a user option can be risky if set too low.
        SecretKeyFactory factory = SecretKeyFactory.getInstance(options.getKdf());
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, SIMPLE_KDF_ITERATION_COUNT, derivedKeyLength);
        byte[] derivedKeyBytes = factory.generateSecret(spec).getEncoded();

        // Split the derived key
        int encKeySizeBytes = options.getKeyLength() / 8;
        int macKeySizeBytes = macKeyLengthBits / 8;
        
        SecretKeySpec encKey = new SecretKeySpec(derivedKeyBytes, 0, encKeySizeBytes, options.getProtocol());
        SecretKeySpec macKey = new SecretKeySpec(derivedKeyBytes, encKeySizeBytes, macKeySizeBytes, MAC_ALGORITHM);
        
        Arrays.fill(derivedKeyBytes, (byte) 0);
        listener.onLog("Key derivation complete.");
        return new SecretKeySpec[]{encKey, macKey};
    }

    // --- SIMPLE STREAM-BASED IMPLEMENTATIONS ---

    private void streamEncrypt(String password, InputStream in, long totalSize, OutputStream out) throws Exception {
        File tempEncryptedFile = null;
        try {
            byte[] salt = generateRandom(SALT_LENGTH_BYTES);
            SecretKeySpec[] keys = deriveKeysSimple(password, salt);
            SecretKeySpec encKey = keys[0];
            SecretKeySpec macKey = keys[1];
            byte[] iv = generateRandom(IV_LENGTH_BYTES);

            out.write(salt);
            out.write(iv);

            tempEncryptedFile = File.createTempFile("enc_simple", ".tmp", context.getCacheDir());
            try (FileOutputStream tempOut = new FileOutputStream(tempEncryptedFile)) {
                Cipher cipher = Cipher.getInstance(SIMPLE_CIPHER_TRANSFORMATION, PROVIDER);
                cipher.init(Cipher.ENCRYPT_MODE, encKey, new IvParameterSpec(iv));

                byte[] buffer = new byte[SIMPLE_CHUNK_SIZE];
                int bytesRead;
                long processedBytes = 0;

                while ((bytesRead = in.read(buffer)) != -1) {
                    byte[] encryptedBytes = cipher.update(buffer, 0, bytesRead);
                    if (encryptedBytes != null) {
                        tempOut.write(encryptedBytes);
                    }
                    processedBytes += bytesRead;
                    reportProgress(processedBytes, totalSize);
                }
                byte[] finalBytes = cipher.doFinal();
                if (finalBytes != null) {
                    tempOut.write(finalBytes);
                }
            }

            byte[] hmacTag = calculateHmac(macKey, tempEncryptedFile);

            try (FileInputStream tempIn = new FileInputStream(tempEncryptedFile)) {
                byte[] buffer = new byte[SIMPLE_CHUNK_SIZE];
                int bytesRead;
                while ((bytesRead = tempIn.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }

            out.write(hmacTag);

        } finally {
            if (tempEncryptedFile != null && tempEncryptedFile.exists()) {
                tempEncryptedFile.delete();
            }
        }
    }


    private void streamDecrypt(String password, InputStream in, long totalSize, OutputStream out) throws Exception {
        File tempCiphertextData = null;
        try {
            byte[] salt = readBytes(in, SALT_LENGTH_BYTES);
            byte[] iv = readBytes(in, IV_LENGTH_BYTES);

            SecretKeySpec[] keys = deriveKeysSimple(password, salt);
            SecretKeySpec encKey = keys[0];
            SecretKeySpec macKey = keys[1];

            tempCiphertextData = File.createTempFile("dec_simple", ".tmp", context.getCacheDir());
            long ciphertextAndMacSize;
            try (FileOutputStream tempOut = new FileOutputStream(tempCiphertextData)) {
                byte[] buffer = new byte[SIMPLE_CHUNK_SIZE];
                int bytesRead;
                ciphertextAndMacSize = 0;
                while ((bytesRead = in.read(buffer)) != -1) {
                    tempOut.write(buffer, 0, bytesRead);
                    ciphertextAndMacSize += bytesRead;
                }
            }

            if (ciphertextAndMacSize < MAC_TAG_LENGTH_BYTES) {
                throw new SecurityException("Invalid data: too short to contain HMAC tag.");
            }

            long ciphertext_size = ciphertextAndMacSize - MAC_TAG_LENGTH_BYTES;
            byte[] calculatedMac = calculateHmac(macKey, tempCiphertextData, 0, ciphertext_size);
            byte[] storedMac = readFromFile(tempCiphertextData, ciphertext_size, MAC_TAG_LENGTH_BYTES);

            if (!MessageDigest.isEqual(calculatedMac, storedMac)) {
                throw new SecurityException("HMAC validation failed: File is corrupt or has been tampered with.");
            }
            listener.onLog("HMAC verification successful.");

            Cipher cipher = Cipher.getInstance(SIMPLE_CIPHER_TRANSFORMATION, PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, encKey, new IvParameterSpec(iv));

            try (FileInputStream tempIn = new FileInputStream(tempCiphertextData)) {
                try(CipherInputStream cipherIn = new CipherInputStream(tempIn, cipher)) {
                    byte[] buffer = new byte[SIMPLE_CHUNK_SIZE];
                    int bytesRead;
                    long processedBytes = 0;
                    while ((bytesRead = cipherIn.read(buffer)) != -1) {
                        out.write(buffer, 0, bytesRead);
                        processedBytes += bytesRead;
                        reportProgress(processedBytes, ciphertext_size);
                    }
                }
            }
        } finally {
            if (tempCiphertextData != null && tempCiphertextData.exists()) {
                tempCiphertextData.delete();
            }
        }
    }

    // --- HELPER METHODS ---
    private byte[] calculateHmac(SecretKeySpec macKey, File file) throws Exception {
        return calculateHmac(macKey, file, 0, file.length());
    }
    
    private byte[] calculateHmac(SecretKeySpec macKey, File file, long offset, long length) throws Exception {
        Mac mac = Mac.getInstance(MAC_ALGORITHM);
        mac.init(macKey);
        try (FileInputStream in = new FileInputStream(file)) {
            if (offset > 0) {
                in.skip(offset);
            }
            byte[] buffer = new byte[SIMPLE_CHUNK_SIZE];
            int bytesRead;
            long remaining = length;
            while (remaining > 0 && (bytesRead = in.read(buffer, 0, (int) Math.min(buffer.length, remaining))) != -1) {
                mac.update(buffer, 0, bytesRead);
                remaining -= bytesRead;
            }
        }
        return mac.doFinal();
    }
    
    private byte[] readFromFile(File file, long offset, int length) throws Exception {
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            raf.seek(offset);
            byte[] data = new byte[length];
            int bytesRead = raf.read(data);
            if (bytesRead != length) {
                throw new Exception("Could not read expected bytes from file.");
            }
            return data;
        }
    }

    private SecretKeySpec[] deriveKeysSimple(String password, byte[] salt) throws Exception {
        int derivedKeyLength = SIMPLE_KEY_LENGTH_BITS * 2;
        SecretKeyFactory factory = SecretKeyFactory.getInstance(SIMPLE_KEY_DERIVATION_ALGORITHM);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, SIMPLE_KDF_ITERATION_COUNT, derivedKeyLength);
        byte[] derivedKeyBytes = factory.generateSecret(spec).getEncoded();

        int keySizeBytes = SIMPLE_KEY_LENGTH_BITS / 8;
        SecretKeySpec encKey = new SecretKeySpec(derivedKeyBytes, 0, keySizeBytes, SIMPLE_ENCRYPTION_ALGORITHM);
        SecretKeySpec macKey = new SecretKeySpec(derivedKeyBytes, keySizeBytes, keySizeBytes, MAC_ALGORITHM);
        
        Arrays.fill(derivedKeyBytes, (byte) 0);

        return new SecretKeySpec[]{encKey, macKey};
    }

    private byte[] generateRandom(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private byte[] readBytes(InputStream in, int length) throws Exception {
        byte[] bytes = new byte[length];
        int bytesRead = in.read(bytes);
        if (bytesRead < length) {
            throw new Exception("Could not read required bytes from stream (salt/iv). Expected " + length + ", got " + bytesRead);
        }
        return bytes;
    }

    private void reportProgress(long processed, long total) {
        if (listener != null && total > 0) {
            int progress = (int) Math.min(100, (processed * 100) / total);
            if (progress > listener.getLastReportedProgress()) {
                 listener.onProgress(progress);
            }
        }
    }
}
