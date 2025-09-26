
package com.example.myapplication.crypto;

import android.content.Context;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
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

    private static final String MAC_ALGORITHM = "HmacSHA256";
    private static final String PROVIDER = "BC";
    private static final int SALT_LENGTH_BYTES = 16;
    private static final int IV_LENGTH_BYTES = 16;
    private static final int MAC_TAG_LENGTH_BYTES = 32;
    private static final int SIMPLE_KDF_ITERATION_COUNT = 65536;

    // Constants for simple mode
    private static final String SIMPLE_KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String SIMPLE_ENCRYPTION_ALGORITHM = "AES";
    private static final String SIMPLE_CIPHER_TRANSFORMATION = "AES/CTR/NoPadding";
    private static final int SIMPLE_KEY_LENGTH_BITS = 256;
    private static final int SIMPLE_CHUNK_SIZE = 64 * 1024;

    public interface HeaderCallback {
        void onHeaderRead(FileHeader header);
        void onError(Exception e);
    }

    public CryptoManager(CryptoListener listener, Context context) {
        this.listener = listener;
        this.context = context;
    }

    // --- PUBLIC API ---

    public void encrypt(String password, InputStream inputStream, long totalSize, OutputStream outputStream, boolean useMultithreading) {
        new Thread(() -> {
            try {
                streamEncryptSimple(password, inputStream, totalSize, outputStream);
                listener.onSuccess("Encryption successful.");
            } catch (Exception e) {
                e.printStackTrace();
                listener.onError("Encryption failed: " + e.getMessage());
            }
        }).start();
    }

    public void decrypt(String password, InputStream inputStream, long totalSize, OutputStream outputStream, boolean useMultithreading) {
        new Thread(() -> {
            try {
                streamDecryptSimple(password, inputStream, totalSize, outputStream);
                listener.onSuccess("Decryption successful.");
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
    
    public void decryptAdvanced(String password, InputStream inputStream, long totalSize, OutputStream outputStream) {
        new Thread(() -> {
            try {
                streamDecryptAdvanced(password, inputStream, totalSize, outputStream);
                listener.onSuccess("Advanced decryption and verification successful.");
            } catch (Exception e) {
                e.printStackTrace();
                listener.onError("Advanced decryption failed: " + e.getMessage());
            }
        }).start();
    }
    
    public void readHeader(InputStream in, HeaderCallback callback) {
        new Thread(() -> {
            try {
                FileHeader header = readHeaderInternal(in);
                callback.onHeaderRead(header);
            } catch (Exception e) {
                callback.onError(e);
            }
        }).start();
    }

    // --- STREAMING METHODS ---

    private void streamEncryptSimple(String password, InputStream in, long totalSize, OutputStream out) throws Exception {
        byte[] salt = generateRandom(SALT_LENGTH_BYTES);
        out.write(salt);

        SecretKeySpec key = deriveKeySimple(password, salt);
        
        byte[] iv = generateRandom(IV_LENGTH_BYTES);
        out.write(iv);

        Cipher cipher = Cipher.getInstance(SIMPLE_CIPHER_TRANSFORMATION, PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        try (CipherOutputStream cipherOut = new CipherOutputStream(out, cipher)) {
            byte[] buffer = new byte[SIMPLE_CHUNK_SIZE];
            int bytesRead;
            long processedBytes = 0;
            while ((bytesRead = in.read(buffer)) != -1) {
                cipherOut.write(buffer, 0, bytesRead);
                processedBytes += bytesRead;
                reportProgress(processedBytes, totalSize);
            }
        }
    }

    private void streamDecryptSimple(String password, InputStream in, long totalSize, OutputStream out) throws Exception {
        byte[] salt = readBytes(in, SALT_LENGTH_BYTES);
        SecretKeySpec key = deriveKeySimple(password, salt);

        byte[] iv = readBytes(in, IV_LENGTH_BYTES);
        
        Cipher cipher = Cipher.getInstance(SIMPLE_CIPHER_TRANSFORMATION, PROVIDER);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        long encryptedDataSize = totalSize - SALT_LENGTH_BYTES - IV_LENGTH_BYTES;

        try (CipherInputStream cipherIn = new CipherInputStream(in, cipher)) {
            byte[] buffer = new byte[SIMPLE_CHUNK_SIZE];
            int bytesRead;
            long processedBytes = 0;
            while ((bytesRead = cipherIn.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
                processedBytes += bytesRead;
                reportProgress(processedBytes, encryptedDataSize);
            }
        }
    }

    private void streamEncryptAdvanced(String password, InputStream in, long totalSize, OutputStream out, CryptoOptions options) throws Exception {
        File tempEncryptedFile = null;
        try {
            // 1. Write header (Length-Prefixed)
            FileHeader header = new FileHeader(options);
            byte[] jsonBytes = header.toJson().getBytes(StandardCharsets.UTF_8);
            byte[] lengthBytes = intToBytes(jsonBytes.length);
            out.write(lengthBytes);
            out.write(jsonBytes);
            listener.onLog("File header written (" + (lengthBytes.length + jsonBytes.length) + " bytes).");

            // 2. Derive keys
            byte[] salt = generateRandom(SALT_LENGTH_BYTES);
            SecretKeySpec[] keys = deriveKeysAdvanced(password, salt, options);
            SecretKeySpec encKey = keys[0];
            SecretKeySpec macKey = keys[1];

            // 3. Write Salt and IV
            byte[] iv = generateRandom(IV_LENGTH_BYTES);
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
            byte[] hmacTag = calculateHmac(macKey, tempEncryptedFile, 0, tempEncryptedFile.length(), options.getChunkSize());
            listener.onLog("HMAC tag calculated.");

            // 6. Write encrypted data from temp file to the final output stream
            try (FileInputStream tempIn = new FileInputStream(tempEncryptedFile)) {
                byte[] buffer = new byte[options.getChunkSize()];
                int bytesRead;
                while ((bytesRead = tempIn.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }

            // 7. Append the HMAC tag to the final output
            out.write(hmacTag);
            listener.onLog("Encrypted data and HMAC tag written to final output.");

        } finally {
            if (tempEncryptedFile != null && tempEncryptedFile.exists()) {
                tempEncryptedFile.delete();
            }
        }
    }

    private void streamDecryptAdvanced(String password, InputStream in, long totalSize, OutputStream out) throws Exception {
        File tempCiphertextData = null;
        try {
            // 1. Read Header to get options
            listener.onLog("Reading file header...");
            FileHeader header = readHeaderInternal(in);
            CryptoOptions options = header.getOptions();
            listener.onLog("Header found: " + options.toString());

            // 2. Read Salt and IV
            byte[] salt = readBytes(in, SALT_LENGTH_BYTES);
            byte[] iv = readBytes(in, IV_LENGTH_BYTES);
            listener.onLog("Salt and IV read.");

            // 3. Derive keys using parameters from header
            SecretKeySpec[] keys = deriveKeysAdvanced(password, salt, options);
            SecretKeySpec encKey = keys[0];
            SecretKeySpec macKey = keys[1];

            // 4. Stream ciphertext + HMAC to a temp file
            listener.onLog("Buffering encrypted content to temporary file...");
            tempCiphertextData = File.createTempFile("dec_adv", ".tmp", context.getCacheDir());
            long ciphertextAndMacSize = 0;
            try (FileOutputStream tempOut = new FileOutputStream(tempCiphertextData)) {
                byte[] buffer = new byte[options.getChunkSize()];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    tempOut.write(buffer, 0, bytesRead);
                    ciphertextAndMacSize += bytesRead;
                }
            }

            if (ciphertextAndMacSize < MAC_TAG_LENGTH_BYTES) {
                throw new SecurityException("Invalid data: too short to contain HMAC tag.");
            }

            // 5. Verify HMAC
            listener.onLog("Verifying file integrity (HMAC)...");
            long ciphertext_size = ciphertextAndMacSize - MAC_TAG_LENGTH_BYTES;
            byte[] calculatedMac = calculateHmac(macKey, tempCiphertextData, 0, ciphertext_size, options.getChunkSize());
            byte[] storedMac = readFromFile(tempCiphertextData, ciphertext_size, MAC_TAG_LENGTH_BYTES);

            if (!MessageDigest.isEqual(calculatedMac, storedMac)) {
                throw new SecurityException("HMAC validation failed: File is corrupt or has been tampered with.");
            }
            listener.onLog("HMAC verification successful.");

            // 6. Decrypt from temp file
            listener.onLog("Decrypting data...");
            Cipher cipher = Cipher.getInstance(options.getCipherTransformation(), PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, encKey, new IvParameterSpec(iv));

            try (FileInputStream tempIn = new FileInputStream(tempCiphertextData)) {
                try (CipherInputStream cipherIn = new CipherInputStream(tempIn, cipher)) {
                    byte[] buffer = new byte[options.getChunkSize()];
                    int bytesRead;
                    long processedBytes = 0;
                    while ((bytesRead = cipherIn.read(buffer)) != -1) {
                        if (processedBytes + bytesRead > ciphertext_size) {
                             out.write(buffer, 0, (int)(ciphertext_size - processedBytes));
                             break;
                        }
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
    
    private FileHeader readHeaderInternal(InputStream in) throws Exception {
        byte[] lengthBytes = readBytes(in, 4);
        int headerLength = bytesToInt(lengthBytes);
        if(headerLength <= 0 || headerLength > 1024) { // Sanity check for 1KB max header
            throw new JSONException("Invalid or corrupt header length: " + headerLength);
        }
        byte[] jsonBytes = readBytes(in, headerLength);
        String jsonString = new String(jsonBytes, StandardCharsets.UTF_8);
        return FileHeader.fromJson(jsonString);
    }

    private SecretKeySpec deriveKeySimple(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(SIMPLE_KEY_DERIVATION_ALGORITHM);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, SIMPLE_KDF_ITERATION_COUNT, SIMPLE_KEY_LENGTH_BITS);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, SIMPLE_ENCRYPTION_ALGORITHM);
        Arrays.fill(keyBytes, (byte) 0); // zero out key material
        return secretKey;
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
        Arrays.fill(derivedKeyBytes, (byte) 0); // zero out key material
        listener.onLog("Key derivation complete.");
        return new SecretKeySpec[]{encKey, macKey};
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

    private byte[] generateRandom(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private byte[] readBytes(InputStream in, int length) throws Exception {
        byte[] bytes = new byte[length];
        int bytesRead = 0;
        int offset = 0;
        while(offset < length && (bytesRead = in.read(bytes, offset, length - offset)) != -1) {
            offset += bytesRead;
        }
        if (offset < length) {
            throw new Exception("Could not read required bytes from stream. Expected " + length + ", got " + offset);
        }
        return bytes;
    }
    
    private int bytesToInt(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) |
               ((bytes[1] & 0xFF) << 16) |
               ((bytes[2] & 0xFF) << 8)  |
               ((bytes[3] & 0xFF));
    }

    private byte[] intToBytes(int value) {
        return new byte[] {
            (byte)(value >> 24),
            (byte)(value >> 16),
            (byte)(value >> 8),
            (byte)value
        };
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
