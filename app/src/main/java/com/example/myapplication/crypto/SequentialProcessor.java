package com.example.myapplication.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A processor that encrypts or decrypts a file using a single thread.
 * This processor now works with file paths to be compatible with the CryptoManager.
 * It is suitable for modes that are not parallelizable (e.g., CBC).
 */
public class SequentialProcessor implements CryptoProcessor {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Override
    public void encrypt(String sourceFilePath, String destFilePath, char[] password, CryptoOptions options, int chunkSize, int threads, CryptoListener listener) throws Exception {
        if (listener == null) listener = CryptoListener.DEFAULT;
        File sourceFile = new File(sourceFilePath);
        long fileLength = sourceFile.length();

        try {
            byte[] salt = Utils.generateRandomBytes(16);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(options.getKdf().toString(), BouncyCastleProvider.PROVIDER_NAME);
            PBEKeySpec spec = new PBEKeySpec(password, salt, 65536, options.getKeyLength());
            SecretKey secretKey = factory.generateSecret(spec);
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), options.getProtocol().name());

            byte[] iv = Utils.generateRandomBytes(options.getIvLengthBytes());

            Cipher cipher = Cipher.getInstance(options.getCipherTransformation(), BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

            try (FileOutputStream fos = new FileOutputStream(destFilePath)) {
                FileHeader header = new FileHeader(options, salt, iv);
                header.writeTo(fos);

                // Encrypt the content
                try (FileInputStream fis = new FileInputStream(sourceFile);
                     CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
                    
                    byte[] buffer = new byte[chunkSize > 0 ? chunkSize : 8192];
                    int bytesRead;
                    long totalBytesRead = 0;
                    listener.onStart(fileLength);

                    while ((bytesRead = fis.read(buffer)) != -1) {
                        cos.write(buffer, 0, bytesRead);
                        totalBytesRead += bytesRead;
                        listener.onProgress(totalBytesRead, fileLength);
                    }
                }
            }
            listener.onSuccess("File encrypted successfully.");

        } catch (Exception e) {
            new File(destFilePath).delete(); // Cleanup partially created file
            listener.onError("Sequential encryption failed: " + e.getMessage(), e);
            throw e;
        }
    }

    @Override
    public void decrypt(String sourceFilePath, String destFilePath, char[] password, int chunkSize, int threads, CryptoListener listener) throws Exception {
        if (listener == null) listener = CryptoListener.DEFAULT;

        try (FileInputStream fis = new FileInputStream(sourceFilePath)) {
            FileHeader header = FileHeader.readFrom(fis);
            CryptoOptions options = header.getOptions();
            int headerSize = header.getHeaderSize();

            SecretKeyFactory factory = SecretKeyFactory.getInstance(options.getKdf().toString(), BouncyCastleProvider.PROVIDER_NAME);
            PBEKeySpec spec = new PBEKeySpec(password, header.getSalt(), 65536, options.getKeyLength());
            SecretKey secretKey = factory.generateSecret(spec);
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), options.getProtocol().name());

            Cipher cipher = Cipher.getInstance(options.getCipherTransformation(), BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(header.getIv()));
            
            long fileLength = new File(sourceFilePath).length();
            long contentLength = fileLength - headerSize;
            if (contentLength < 0) contentLength = 0;

            // Decrypt the content
            try (CipherInputStream cis = new CipherInputStream(fis, cipher);
                 FileOutputStream fos = new FileOutputStream(destFilePath)) {

                byte[] buffer = new byte[chunkSize > 0 ? chunkSize : 8192];
                int bytesRead;
                long totalBytesRead = 0;
                listener.onStart(contentLength);

                while ((bytesRead = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                    totalBytesRead += bytesRead;
                    listener.onProgress(totalBytesRead, contentLength);
                }
            }
            listener.onSuccess("File decrypted successfully.");
        } catch (Exception e) {
            new File(destFilePath).delete(); // Cleanup partially created file
            listener.onError("Sequential decryption failed: " + e.getMessage(), e);
            throw e;
        }
    }
}
