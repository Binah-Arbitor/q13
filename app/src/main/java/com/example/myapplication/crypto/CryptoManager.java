package com.example.myapplication.crypto;

import org.spongycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.KeySpec;
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


    public CryptoManager(CryptoListener listener) {
        this.listener = listener;
    }

    public void encrypt(String password, String inputFile, String outputFile) throws Exception {
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be empty");
        }

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[KDF_SALT_LENGTH];
            random.nextBytes(salt);

            byte[] iv = new byte[GCM_IV_LENGTH];
            random.nextBytes(iv);

            fos.write(salt);
            fos.write(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGORITHM);
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, KDF_ITERATION_COUNT, KEY_LENGTH);
            SecretKeySpec secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), ALGORITHM);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION, CIPHER_PROVIDER);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

            try (CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                long totalBytes = fis.getChannel().size();
                long bytesProcessed = 0;

                while ((bytesRead = fis.read(buffer)) != -1) {
                    cos.write(buffer, 0, bytesRead);
                    bytesProcessed += bytesRead;
                    if (listener != null) {
                        listener.onProgress((int) ((bytesProcessed * 100) / totalBytes));
                    }
                }
            }
            if (listener != null) {
                listener.onSuccess("Encryption completed successfully.");
            }
        } catch (Exception e) {
            if (listener != null) {
                listener.onError(e.getMessage());
            }
            throw e;
        }
    }

    public void decrypt(String password, String inputFile, String outputFile) throws Exception {
         if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be empty");
        }

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            byte[] salt = new byte[KDF_SALT_LENGTH];
            if (fis.read(salt) != KDF_SALT_LENGTH) {
                throw new IllegalArgumentException("Invalid encrypted file format (salt).");
            }

            byte[] iv = new byte[GCM_IV_LENGTH];
            if (fis.read(iv) != GCM_IV_LENGTH) {
                 throw new IllegalArgumentException("Invalid encrypted file format (iv).");
            }

            SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGORITHM);
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, KDF_ITERATION_COUNT, KEY_LENGTH);
            SecretKeySpec secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), ALGORITHM);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION, CIPHER_PROVIDER);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

            try (CipherInputStream cis = new CipherInputStream(fis, cipher)) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                long totalBytes = fis.getChannel().size() + KDF_SALT_LENGTH + GCM_IV_LENGTH;
                long bytesProcessed = KDF_SALT_LENGTH + GCM_IV_LENGTH;


                while ((bytesRead = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                    bytesProcessed += bytesRead; 
                    if (listener != null) {
                        int progress = (int) ((bytesProcessed * 100) / totalBytes);
                        listener.onProgress(progress > 100 ? 100 : progress);
                    }
                }
            }
             if (listener != null) {
                listener.onSuccess("Decryption completed successfully.");
            }
        } catch (Exception e) {
            if (listener != null) {
                if (e instanceof javax.crypto.AEADBadTagException) {
                     listener.onError("Decryption failed. Please check your password or the file integrity. " + e.getMessage());
                } else {
                     listener.onError(e.getMessage());
                }
            }
            throw e;
        }
    }
}
