package com.example.myapplication.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class SequentialProcessor implements CryptoProcessor {

    @Override
    public void encrypt(String sourcePath, String destPath, char[] password, CryptoOptions options, int chunkSize, CryptoListener listener) throws Exception {
        FileHeader header;
        try (FileInputStream fis = new FileInputStream(sourcePath);
             FileOutputStream fos = new FileOutputStream(destPath)) {

            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);

            SecretKeySpec key = KeyDerivation.deriveKey(password, salt, options.getKdf(), options.getKeyLength(), options.getProtocol().isXTS());

            byte[] iv = new byte[options.getBlockSizeBits() / 8];
            new SecureRandom().nextBytes(iv);
            
            header = new FileHeader(options, salt, iv);

            Cipher cipher = Cipher.getInstance(options.getTransformation());
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

            fos.write(header.getHeaderBytes());

            long fileLength = new File(sourcePath).length();
            listener.onStart(fileLength);

            CipherOutputStream cos = new CipherOutputStream(fos, cipher);
            byte[] buffer = new byte[chunkSize];
            int len;
            long totalRead = 0;
            while ((len = fis.read(buffer)) != -1) {
                cos.write(buffer, 0, len);
                totalRead += len;
                listener.onProgress(totalRead, fileLength);
            }
            cos.close(); // Important: flushes the final block
            listener.onSuccess("Encryption complete. Output: " + destPath);
        }
    }

    @Override
    public void decrypt(String sourcePath, String destPath, char[] password, CryptoOptions manualOptions, int chunkSize, CryptoListener listener) throws Exception {
        try (FileInputStream fis = new FileInputStream(sourcePath);
             FileOutputStream fos = new FileOutputStream(destPath)) {

            FileHeader header;
            CryptoOptions options;
            SecretKeySpec key;
            byte[] iv;

            if (manualOptions != null) {
                // Manual mode: Options are provided by the user.
                options = manualOptions;
                byte[] salt = new byte[16]; // Dummy salt for key derivation, not used for decryption itself
                key = KeyDerivation.deriveKey(password, salt, options.getKdf(), options.getKeyLength(), options.getProtocol().isXTS());
                iv = new byte[options.getBlockSizeBits() / 8]; // Dummy IV, not used for decryption
                header = new FileHeader(options, salt, iv); // Header not read from file

            } else {
                // Automatic mode: Read header from the file.
                header = FileHeader.fromStream(fis);
                options = header.getOptions();
                iv = header.getIv();
                key = KeyDerivation.deriveKey(password, header.getSalt(), options.getKdf(), options.getKeyLength(), options.getProtocol().isXTS());
            }
            
            Cipher cipher = Cipher.getInstance(options.getTransformation());
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

            long fileLength = new File(sourcePath).length();
            long headerSize = (manualOptions == null) ? header.getHeaderSize() : 0;
            long contentLength = fileLength - headerSize;
            listener.onStart(contentLength);

            CipherInputStream cis = new CipherInputStream(fis, cipher);
            byte[] buffer = new byte[chunkSize];
            int len;
            long totalRead = 0;
            while ((len = cis.read(buffer)) != -1) {
                fos.write(buffer, 0, len);
                totalRead += len;
                listener.onProgress(totalRead, contentLength);
            }
            cis.close();
            listener.onSuccess("Decryption complete. Output: " + destPath);
        }
    }
}
