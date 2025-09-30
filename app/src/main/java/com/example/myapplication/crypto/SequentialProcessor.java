package com.example.myapplication.crypto;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

public class SequentialProcessor implements CryptoProcessor {

    @Override
    public void encrypt(String sourceFilePath, String destFilePath, char[] password, CryptoOptions options, int chunkSize, int threads, CryptoListener listener) throws Exception {
        FileHeader header = new FileHeader(options);
        byte[] salt = Utils.generateRandomBytes(16);
        header.setSalt(salt);

        SecretKeySpec key = KeyDerivation.deriveKey(password, salt, options.getKdf(), options.getKeyLength(), options.getProtocol().isXTS());

        byte[] iv = Utils.generateRandomBytes(options.getIvLengthBytes());
        header.setIv(iv);

        Cipher cipher = options.getProtocol().getInitialisedCipher(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        try (FileOutputStream fos = new FileOutputStream(destFilePath)) {
            fos.write(header.getHeaderBytes());

            try (FileInputStream fis = new FileInputStream(sourceFilePath)) {
                long fileLength = new File(sourceFilePath).length();
                listener.onStart(fileLength);

                byte[] buffer = new byte[chunkSize];
                int bytesRead;
                long totalBytesRead = 0;

                while ((bytesRead = fis.read(buffer)) != -1) {
                    byte[] encryptedBytes = cipher.update(buffer, 0, bytesRead);
                    if (encryptedBytes != null) {
                        fos.write(encryptedBytes);
                    }
                    totalBytesRead += bytesRead;
                    listener.onProgress(totalBytesRead, fileLength);
                }
                byte[] finalBytes = cipher.doFinal();
                if (finalBytes != null) {
                    fos.write(finalBytes);
                }
            }
        }
        listener.onSuccess("Encryption completed successfully. File saved to: " + destFilePath);
    }

    @Override
    public void decrypt(String sourceFilePath, String destFilePath, char[] password, CryptoOptions manualOptions, int chunkSize, int threads, CryptoListener listener) throws Exception {
        try (FileInputStream fis = new FileInputStream(sourceFilePath)) {
            CryptoOptions options;
            SecretKeySpec key;
            Cipher cipher;

            if (manualOptions != null) {
                // Manual Mode
                options = manualOptions;
                byte[] salt = Utils.generateRandomBytes(16); // Dummy salt for key derivation if not available
                byte[] iv = Utils.generateRandomBytes(options.getIvLengthBytes()); // Dummy IV
                 // In a true manual scenario, user might need to input these, but for now, we make assumptions.
                key = KeyDerivation.deriveKey(password, salt, options.getKdf(), options.getKeyLength(), options.getProtocol().isXTS());
                cipher = options.getProtocol().getInitialisedCipher(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                // No header to skip in manual mode

            } else {
                // Automatic Mode (Header-based)
                FileHeader header = FileHeader.fromStream(fis);
                options = header.getOptions();
                key = KeyDerivation.deriveKey(password, header.getSalt(), options.getKdf(), options.getKeyLength(), options.getProtocol().isXTS());
                cipher = options.getProtocol().getInitialisedCipher(Cipher.DECRYPT_MODE, key, new IvParameterSpec(header.getIv()));
            }

            long fileLength = new File(sourceFilePath).length();
            long contentLength = manualOptions == null ? fileLength - FileHeader.HEADER_SIZE : fileLength;
            listener.onStart(contentLength);

            try (FileOutputStream fos = new FileOutputStream(destFilePath); CipherInputStream cis = new CipherInputStream(fis, cipher)) {

                byte[] buffer = new byte[chunkSize];
                int bytesRead;
                long totalBytesRead = 0;

                while ((bytesRead = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                    totalBytesRead += bytesRead;
                    listener.onProgress(totalBytesRead, contentLength);
                }
            }
        }
        listener.onSuccess("Decryption completed successfully. File saved to: " + destFilePath);
    }
}
