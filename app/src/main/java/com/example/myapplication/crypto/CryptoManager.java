
package com.example.myapplication.crypto;

import android.content.Context;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONException;

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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

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
            // 1. Create and write header
            FileHeader header = new FileHeader(options);
            byte[] headerBytes = header.toBytes();
            out.write(headerBytes);
            listener.onLog("File header written (" + headerBytes.length + " bytes).");

            // 2. Derive keys from password using advanced options
            byte[] salt = generateRandom(SALT_LENGTH_BYTES);
            SecretKeySpec[] keys = deriveKeysAdvanced(password, salt, options);
            SecretKeySpec encKey = keys[0];
            SecretKeySpec macKey = keys[1];

            // 3. Generate IV
            byte[] iv = generateRandom(IV_LENGTH_BYTES);

            // 4. Write Salt and IV to the final output stream
            out.write(salt);
            out.write(iv);
            listener.onLog("Salt and IV written.");

            // 5. Encrypt data to a temporary file
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

            // 6. Calculate HMAC of the encrypted temporary file
            listener.onLog("Calculating HMAC tag...");
            byte[] hmacTag = calculateHmac(macKey, tempEncryptedFile, options.getChunkSize());
            listener.onLog("HMAC tag calculated.");

            // 7. Stream the encrypted data from temp file to the final output stream
            try (FileInputStream tempIn = new FileInputStream(tempEncryptedFile)) {
                byte[] buffer = new byte[options.getChunkSize()];
                int bytesRead;
                while ((bytesRead = tempIn.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }

            // 8. Write HMAC tag to the final output stream
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
        int macKeyLengthBits = 256;
        int derivedKeyLength = options.getKeyLength() + macKeyLengthBits;
        SecretKeyFactory factory = SecretKeyFactory.getInstance(options.getKdf());
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, SIMPLE_KDF_ITERATION_COUNT, derivedKeyLength);
        byte[] derivedKeyBytes = factory.generateSecret(spec).getEncoded();

        int encKeySizeBytes = options.getKeyLength() / 8;
        int macKeySizeBytes = macKeyLengthBits / 8;
        SecretKeySpec encKey = new SecretKeySpec(derivedKeyBytes, 0, encKeySizeBytes, options.getProtocol());
        SecretKeySpec macKey = new SecretKeySpec(derivedKeyBytes, encKeySizeBytes, macKeySizeBytes, MAC_ALGORITHM);
        Arrays.fill(derivedKeyBytes, (byte) 0);
        listener.onLog("Key derivation complete.");
        return new SecretKeySpec[]{encKey, macKey};
    }

    // --- SIMPLE STREAM-BASED IMPLEMENTATIONS (Unchanged) ---
    private void streamEncrypt(String password, InputStream in, long totalSize, OutputStream out) throws Exception { 
        // ... (existing simple encryption code) 
    }
    private void streamDecrypt(String password, InputStream in, long totalSize, OutputStream out) throws Exception { 
        // ... (existing simple decryption code) 
    }

    // --- HELPER METHODS ---
    private byte[] calculateHmac(SecretKeySpec macKey, File file, int chunkSize) throws Exception {
        return calculateHmac(macKey, file, 0, file.length(), chunkSize);
    }

    private byte[] calculateHmac(SecretKeySpec macKey, File file, long offset, long length, int chunkSize) throws Exception {
        Mac mac = Mac.getInstance(MAC_ALGORITHM);
        mac.init(macKey);
        try (FileInputStream in = new FileInputStream(file)) {
            if (offset > 0) {
                in.skip(offset);
            }
            byte[] buffer = new byte[chunkSize];
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
        // ... (existing simple key derivation code)
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
            throw new Exception("Could not read required bytes from stream. Expected " + length + ", got " + bytesRead);
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
