package com.example.myapplication.crypto;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

public class SequentialProcessor implements CryptoProcessor {

    @Override
    public void encrypt(String sourcePath, String destPath, char[] password, CryptoOptions options, int chunkSize, int threads, CryptoListener listener) throws Exception {
        try (FileInputStream fis = new FileInputStream(sourcePath);
             FileOutputStream fos = new FileOutputStream(destPath)) {

            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);

            SecretKeySpec key = KeyDerivation.deriveKey(password, salt, options.getKdf(), options.getKeyLength(), options.getProtocol().isXTS());

            // For GCM and CCM, IV should be 12 bytes (96 bits) for performance and security.
            int ivLength = (options.getMode() == CryptoOptions.CipherMode.GCM || options.getMode() == CryptoOptions.CipherMode.CCM) ? 12 : options.getBlockSizeBits() / 8;
            byte[] iv = new byte[ivLength];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance(options.getTransformation());
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

            FileHeader header = new FileHeader(options, salt, iv);
            fos.write(header.getHeaderBytes());

            // Use the header as Associated Additional Data (AAD) for authenticated ciphers
            if (options.requiresAAD()) {
                cipher.updateAAD(header.getAADBytes());
            }

            long fileLength = new File(sourcePath).length();
            listener.onStart(fileLength);

            byte[] buffer = new byte[chunkSize];
            int len;
            long totalRead = 0;
            while ((len = fis.read(buffer)) != -1) {
                byte[] encryptedPart = cipher.update(buffer, 0, len);
                if (encryptedPart != null) {
                    fos.write(encryptedPart);
                }
                totalRead += len;
                listener.onProgress(totalRead, fileLength);
            }

            byte[] finalPart = cipher.doFinal(); // This includes the authentication tag for GCM/CCM
            fos.write(finalPart);

            listener.onSuccess("Encryption complete.", destPath);
        }
    }

    @Override
    public void decrypt(String sourcePath, String destPath, char[] password, CryptoOptions manualOptions, int chunkSize, int threads, CryptoListener listener) throws Exception {
        File tempFile = new File(destPath + ".tmp");
        try (FileInputStream fis = new FileInputStream(sourcePath);
             FileOutputStream fos_temp = new FileOutputStream(tempFile)) {

            FileHeader header = (manualOptions == null) ? FileHeader.fromStream(fis) : null;
            CryptoOptions options = (manualOptions == null) ? header.getOptions() : manualOptions;
            
            // For decryption, IV must be read from the header
            byte[] iv;
            byte[] salt;

            if (header != null) {
                iv = header.getIv();
                salt = header.getSalt();
            } else {
                // Manual mode is tricky for GCM as we don't know the IV. 
                // This implementation assumes a non-GCM cipher or that IV is handled elsewhere.
                // A truly robust manual GCM would need the IV passed in.
                int ivLength = (options.getMode() == CryptoOptions.CipherMode.GCM || options.getMode() == CryptoOptions.CipherMode.CCM) ? 12 : options.getBlockSizeBits() / 8;
                iv = new byte[ivLength];
                salt = new byte[16]; // Dummy salt for manual mode
            }

            SecretKeySpec key = KeyDerivation.deriveKey(password, salt, options.getKdf(), options.getKeyLength(), options.getProtocol().isXTS());

            Cipher cipher = Cipher.getInstance(options.getTransformation());
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

            if (header != null && options.requiresAAD()) {
                 cipher.updateAAD(header.getAADBytes());
            }

            long fileLength = new File(sourcePath).length();
            long headerSize = (header != null) ? header.getHeaderSize() : 0;
            long contentLength = fileLength - headerSize;
            listener.onStart(contentLength);

            byte[] buffer = new byte[chunkSize];
            int len;
            long totalRead = 0;

            while ((len = fis.read(buffer)) != -1) {
                // Handle the last chunk carefully for authenticated ciphers
                int bytesToProcess = len;
                long remaining = contentLength - totalRead;
                if (bytesToProcess > remaining) { // Should not happen with correct content length
                    bytesToProcess = (int) remaining;
                }

                byte[] decryptedPart = cipher.update(buffer, 0, bytesToProcess);
                if (decryptedPart != null) {
                    fos_temp.write(decryptedPart);
                }
                totalRead += bytesToProcess;
                if(totalRead >= contentLength) break; // Exit loop if all content is read
            }
            listener.onProgress(totalRead, contentLength);
            
            try {
                byte[] finalPart = cipher.doFinal(); // Verifies the tag. Throws AEADBadTagException on failure.
                if (finalPart != null) {
                    fos_temp.write(finalPart);
                }
            } catch (AEADBadTagException e) {
                fos_temp.close();
                tempFile.delete();
                throw new IOException("Decryption failed: Authentication tag mismatch! The file may be corrupt or the password is wrong.", e);
            } 

            fos_temp.close();

            File finalFile = new File(destPath);
            if (finalFile.exists()) {
                finalFile.delete();
            }
            if (!tempFile.renameTo(finalFile)) {
                throw new IOException("Failed to rename temporary file to final destination.");
            }
            listener.onSuccess("Decryption complete.", destPath);

        } catch (Exception e) {
            if (tempFile.exists()) {
                tempFile.delete();
            }
            throw e;
        }
    }
}
