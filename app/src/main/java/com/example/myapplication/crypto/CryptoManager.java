package com.example.myapplication.crypto;

import android.content.Context;
import android.net.Uri;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONException;

import javax.crypto.Cipher;
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
    private static final int MAC_TAG_LENGTH_BYTES = 32;
    private static final int KDF_ITERATION_COUNT = 65536;

    public interface HeaderCallback {
        void onHeaderRead(FileHeader header);
        void onError(Exception e);
    }

    public CryptoManager(CryptoListener listener, Context context) {
        this.listener = listener;
        this.context = context;
    }

    // --- PUBLIC API ---

    public void encrypt(String password, Uri fileUri, boolean useMultithreading) {
        new Thread(() -> {
            File tempFile = null;
            try {
                CryptoOptions simpleOptions = new CryptoOptions(
                    "AES", 256, "CTR", "NoPadding", "PBKDF2WithHmacSHA256",
                    64 * 1024,
                    useMultithreading ? Math.max(1, Runtime.getRuntime().availableProcessors()) : 1
                );

                tempFile = File.createTempFile("enc", ".tmp", context.getCacheDir());

                try (InputStream in = context.getContentResolver().openInputStream(fileUri);
                     FileOutputStream out = new FileOutputStream(tempFile)) {
                    if (in == null) throw new Exception("Failed to open input stream from URI.");
                    long totalSize = context.getContentResolver().openFileDescriptor(fileUri, "r").getStatSize();
                    streamEncrypt(password, in, totalSize, out, simpleOptions);
                }

                replaceFile(tempFile, fileUri);
                listener.onSuccess("Encryption successful.");

            } catch (Exception e) {
                e.printStackTrace();
                listener.onError("Encryption failed: " + e.getMessage());
            } finally {
                if (tempFile != null) tempFile.delete();
            }
        }).start();
    }

    public void decrypt(String password, Uri fileUri, boolean useMultithreading) {
        new Thread(() -> {
            File tempFile = null;
            try {
                tempFile = File.createTempFile("dec", ".tmp", context.getCacheDir());

                try (InputStream in = context.getContentResolver().openInputStream(fileUri);
                     FileOutputStream out = new FileOutputStream(tempFile)) {
                    if (in == null) throw new Exception("Failed to open input stream from URI.");
                     long totalSize = context.getContentResolver().openFileDescriptor(fileUri, "r").getStatSize();
                    streamDecrypt(password, in, totalSize, out);
                }

                replaceFile(tempFile, fileUri);
                listener.onSuccess("Decryption successful.");

            } catch (Exception e) {
                e.printStackTrace();
                listener.onError("Decryption failed: " + e.getMessage());
            } finally {
                if (tempFile != null) tempFile.delete();
            }
        }).start();
    }

    public void encryptAdvanced(String password, Uri fileUri, CryptoOptions options) {
         new Thread(() -> {
            File tempFile = null;
            try {
                tempFile = File.createTempFile("enc_adv", ".tmp", context.getCacheDir());
                try (InputStream in = context.getContentResolver().openInputStream(fileUri);
                     FileOutputStream out = new FileOutputStream(tempFile)) {
                    if (in == null) throw new Exception("Failed to open input stream from URI.");
                    long totalSize = context.getContentResolver().openFileDescriptor(fileUri, "r").getStatSize();
                    streamEncrypt(password, in, totalSize, out, options);
                }
                replaceFile(tempFile, fileUri);
                listener.onSuccess("Advanced encryption successful.");
            } catch (Exception e) {
                e.printStackTrace();
                listener.onError("Advanced encryption failed: " + e.getMessage());
            } finally {
                if (tempFile != null) tempFile.delete();
            }
        }).start();
    }

    public void decryptAdvanced(String password, Uri fileUri) {
        decrypt(password, fileUri, false);
    }

    public void readHeader(Uri fileUri, HeaderCallback callback) {
        new Thread(() -> {
            try (InputStream in = context.getContentResolver().openInputStream(fileUri)) {
                 if (in == null) throw new Exception("Failed to open input stream from URI.");
                FileHeader header = readHeaderInternal(in);
                callback.onHeaderRead(header);
            } catch (Exception e) {
                callback.onError(e);
            }
        }).start();
    }

    // --- CORE STREAMING LOGIC ---

    private void streamEncrypt(String password, InputStream in, long totalSize, OutputStream out, CryptoOptions options) throws Exception {
        // 1. Write header
        FileHeader header = new FileHeader(options);
        byte[] headerBytes = header.toBytes();
        out.write(headerBytes);
        listener.onLog("File header written (" + headerBytes.length + " bytes).");

        // 2. Derive keys
        byte[] salt = generateRandom(SALT_LENGTH_BYTES);
        SecretKeySpec[] keys = deriveKeys(password, salt, options);
        SecretKeySpec encKey = keys[0];
        SecretKeySpec macKey = keys[1];

        // 3. Write Salt and IV
        byte[] iv = generateRandom(options.getIvLengthBytes());
        out.write(salt);
        out.write(iv);
        listener.onLog("Salt and IV written.");

        // 4. Setup MAC and Cipher
        Mac mac = Mac.getInstance(MAC_ALGORITHM);
        mac.init(macKey);
        mac.update(headerBytes);
        mac.update(salt);
        mac.update(iv);

        Cipher cipher = Cipher.getInstance(options.getCipherTransformation(), PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, encKey, new IvParameterSpec(iv));

        // 5. Encrypt data and update HMAC
        byte[] buffer = new byte[options.getChunkSize()];
        int bytesRead;
        long processedBytes = 0;

        while ((bytesRead = in.read(buffer)) != -1) {
            byte[] ciphertext = cipher.update(buffer, 0, bytesRead);
            if (ciphertext != null) {
                out.write(ciphertext);
                mac.update(ciphertext);
            }
            processedBytes += bytesRead;
            reportProgress(processedBytes, totalSize);
        }

        byte[] finalCipherBytes = cipher.doFinal();
        if (finalCipherBytes != null) {
            out.write(finalCipherBytes);
            mac.update(finalCipherBytes);
        }

        // 6. Append HMAC tag
        byte[] hmacTag = mac.doFinal();
        out.write(hmacTag);
        listener.onLog("Encrypted data and HMAC tag written.");
    }

    private void streamDecrypt(String password, InputStream in, long totalSize, OutputStream out) throws Exception {
        // 1. Read Header
        listener.onLog("Reading file header...");
        FileHeader header = readHeaderInternal(in);
        CryptoOptions options = header.getOptions();
        listener.onLog("Header found: " + options.toString());
        byte[] headerBytes = header.toBytes();

        // 2. Read Salt and IV
        byte[] salt = readBytes(in, SALT_LENGTH_BYTES);
        byte[] iv = readBytes(in, options.getIvLengthBytes());
        listener.onLog("Salt and IV read.");
        
        // [임시코드] 디버깅 로그 시작
        listener.onLog("--- DECRYPTION DEBUG START ---");
        listener.onLog("[임시코드] Total file size: " + totalSize);
        listener.onLog("[임시코드] Header size: " + headerBytes.length);
        listener.onLog("[임시코드] Salt size: " + SALT_LENGTH_BYTES);
        listener.onLog("[임시코드] IV size: " + options.getIvLengthBytes());
        listener.onLog("[임시코드] HMAC tag size: " + MAC_TAG_LENGTH_BYTES);
        // [임시코드] 디버깅 로그 끝

        // 3. Derive keys
        SecretKeySpec[] keys = deriveKeys(password, salt, options);
        SecretKeySpec encKey = keys[0];
        SecretKeySpec macKey = keys[1];

        // 4. Setup MAC and Cipher
        Mac mac = Mac.getInstance(MAC_ALGORITHM);
        mac.init(macKey);
        mac.update(headerBytes);
        mac.update(salt);
        mac.update(iv);

        Cipher cipher = Cipher.getInstance(options.getCipherTransformation(), PROVIDER);
        cipher.init(Cipher.DECRYPT_MODE, encKey, new IvParameterSpec(iv));

        // 5. Decrypt and verify HMAC on-the-fly
        listener.onLog("Decrypting and verifying file...");

        long ciphertextLength = totalSize - headerBytes.length - SALT_LENGTH_BYTES - options.getIvLengthBytes() - MAC_TAG_LENGTH_BYTES;
        
        // [임시코드] 디버깅 로그 시작
        listener.onLog("[임시코드] Calculated ciphertext length: " + ciphertextLength);
        // [임시코드] 디버깅 로그 끝

        if (ciphertextLength < 0) {
            throw new SecurityException("Invalid file size. The file is smaller than its metadata indicates.");
        }

        byte[] buffer = new byte[options.getChunkSize()];
        long remaining = ciphertextLength;
        int bytesRead;
        long totalPlaintextBytesWritten = 0; // [임시코드]

        while (remaining > 0 && (bytesRead = in.read(buffer, 0, (int) Math.min(buffer.length, remaining))) != -1) {
             // [임시코드] 디버깅 로그 시작
            if (remaining < (2L * options.getChunkSize()) || bytesRead < buffer.length) {
                listener.onLog("[임시코드] Loop: bytesRead=" + bytesRead + ", remaining=" + remaining);
            }
            // [임시코드] 디버깅 로그 끝
            
            mac.update(buffer, 0, bytesRead);
            byte[] plaintext = cipher.update(buffer, 0, bytesRead);
            if (plaintext != null) {
                out.write(plaintext);
                totalPlaintextBytesWritten += plaintext.length; // [임시코드]
            }
            remaining -= bytesRead;
        }

        byte[] finalPlaintextBytes = cipher.doFinal();
        if (finalPlaintextBytes != null) {
            out.write(finalPlaintextBytes);
            // [임시코드] 디버깅 로그 시작
            listener.onLog("[임시코드] Final plaintext bytes from doFinal(): " + finalPlaintextBytes.length);
            totalPlaintextBytesWritten += finalPlaintextBytes.length;
            // [임시코드] 디버깅 로그 끝
        }
        
        // [임시코드] 디버깅 로그 시작
        listener.onLog("[임시코드] Total plaintext bytes written to temp file: " + totalPlaintextBytesWritten);
        // [임시코드] 디버깅 로그 끝

        // 6. Final HMAC verification
        byte[] storedMac = readBytes(in, MAC_TAG_LENGTH_BYTES);
        byte[] calculatedMac = mac.doFinal();
        
        // [임시코드] 디버깅 로그 시작
        listener.onLog("[임시코드] Stored MAC: " + bytesToHex(storedMac));
        listener.onLog("[임시코드] Calculated MAC: " + bytesToHex(calculatedMac));
        listener.onLog("--- DECRYPTION DEBUG END ---");
        // [임시코드] 디버깅 로그 끝

        if (!MessageDigest.isEqual(storedMac, calculatedMac)) {
            throw new SecurityException("HMAC validation failed: File is corrupt or has been tampered with.");
        }

        listener.onLog("HMAC verification successful.");
    }

    // --- HELPER METHODS ---

    private FileHeader readHeaderInternal(InputStream in) throws Exception {
        byte[] lengthBytes = readBytes(in, 4);
        int headerLength = bytesToInt(lengthBytes);
        if (headerLength <= 0 || headerLength > 2048) {
            throw new JSONException("Invalid or corrupt header length: " + headerLength);
        }
        byte[] jsonBytes = readBytes(in, headerLength);
        String jsonString = new String(jsonBytes, StandardCharsets.UTF_8);
        return FileHeader.fromJson(jsonString);
    }
    
    private SecretKeySpec[] deriveKeys(String password, byte[] salt, CryptoOptions options) throws Exception {
        listener.onLog("Deriving keys with " + options.getKdf() + "...");
        int macKeyLengthBits = 256;
        int derivedKeyLength = options.getKeyLength() + macKeyLengthBits;
        
        SecretKeyFactory factory = SecretKeyFactory.getInstance(options.getKdf());
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, KDF_ITERATION_COUNT, derivedKeyLength);
        byte[] derivedKeyBytes = factory.generateSecret(spec).getEncoded();

        int encKeySizeBytes = options.getKeyLength() / 8;
        int macKeySizeBytes = macKeyLengthBits / 8;
        
        SecretKeySpec encKey = new SecretKeySpec(derivedKeyBytes, 0, encKeySizeBytes, options.getProtocol());
        SecretKeySpec macKey = new SecretKeySpec(derivedKeyBytes, encKeySizeBytes, macKeySizeBytes, MAC_ALGORITHM);
        
        Arrays.fill(derivedKeyBytes, (byte) 0);
        listener.onLog("Key derivation complete.");
        return new SecretKeySpec[]{encKey, macKey};
    }

    private void replaceFile(File sourceFile, Uri targetUri) throws Exception {
        try (FileInputStream fis = new FileInputStream(sourceFile);
             OutputStream out = context.getContentResolver().openOutputStream(targetUri, "w")) {
            if (out == null) {
                throw new Exception("Failed to open output stream to overwrite URI.");
            }
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        }
    }

    private byte[] generateRandom(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private byte[] readBytes(InputStream in, int length) throws Exception {
        byte[] bytes = new byte[length];
        int offset = 0;
        while (offset < length) {
            int read = in.read(bytes, offset, length - offset);
            if (read == -1) {
                throw new Exception("End of stream reached before all bytes could be read. Expected " + length + ", got " + offset);
            }
            offset += read;
        }
        return bytes;
    }

    private int bytesToInt(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) | ((bytes[1] & 0xFF) << 16) | ((bytes[2] & 0xFF) << 8) | ((bytes[3] & 0xFF));
    }

    private void reportProgress(long processed, long total) {
        if (listener != null && total > 0) {
            int progress = (int) Math.min(100, (processed * 100) / total);
            if (progress > listener.getLastReportedProgress()) {
                listener.onProgress(progress);
            }
        }
    }
    
    // [임시코드] 바이트 배열을 16진수 문자열로 변환하는 헬퍼
    private String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        final char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}
