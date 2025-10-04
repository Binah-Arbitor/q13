package com.example.myapplication.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SequentialProcessor implements IProcessor {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    public void encrypt(String sourcePath, String destPath, char[] password, CryptoOptions options, int chunkSize, CryptoListener listener) throws Exception {
        try (FileInputStream fis = new FileInputStream(sourcePath);
             FileOutputStream fos = new FileOutputStream(destPath)) {

            byte[] salt = KeyDerivation.generateSalt();
            SecretKey key = KeyDerivation.deriveKey(password, salt, options.getKdf(), options.getKeyLength());

            byte[] iv = new byte[options.getBlockSizeBits() / 8];
            new SecureRandom().nextBytes(iv);

            FileHeader header = new FileHeader(options, iv, salt);
            header.writeTo(fos);

            String transformation = options.getTransformation();
            Cipher cipher = Cipher.getInstance(transformation, "BC");
            
            AlgorithmParameterSpec spec = getAlgorithmParameterSpec(options, iv);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getEncoded(), options.getProtocol().name()), spec);

            if (options.requiresAAD()) {
                cipher.updateAAD(header.getAADBytes());
            }
            
            listener.onStart(fis.getChannel().size());

            try (CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
                byte[] buffer = new byte[chunkSize];
                int bytesRead;
                long totalBytesRead = 0;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    cos.write(buffer, 0, bytesRead);
                    totalBytesRead += bytesRead;
                    listener.onProgress(totalBytesRead, fis.getChannel().size());
                }
            }
            listener.onSuccess("Encryption completed successfully.", destPath);
        } catch (Exception e) {
            listener.onError("Encryption failed.", e);
            throw e;
        }
    }

    @Override
    public void decrypt(String sourcePath, String destPath, char[] password, CryptoOptions manualOptions, int chunkSize, CryptoListener listener) throws Exception {
        try (FileInputStream fis = new FileInputStream(sourcePath);
             FileOutputStream fos = new FileOutputStream(destPath)) {

            FileHeader header = FileHeader.fromStream(fis);
            CryptoOptions options = header.getOptions();

            // Override with manual options if provided
            if (manualOptions != null) {
                options = manualOptions;
            }

            SecretKey key = KeyDerivation.deriveKey(password, header.getSalt(), options.getKdf(), options.getKeyLength());
            byte[] iv = header.getIv();

            String transformation = options.getTransformation();
            Cipher cipher = Cipher.getInstance(transformation, "BC");
            
            AlgorithmParameterSpec spec = getAlgorithmParameterSpec(options, iv);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getEncoded(), options.getProtocol().name()), spec);

            if (options.requiresAAD()) {
                cipher.updateAAD(header.getAADBytes());
            }

            long fileLength = new java.io.File(sourcePath).length();
            long headerSize = header.getHeaderSize();
            long ciphertextLength = fileLength - headerSize;
            
            listener.onStart(ciphertextLength);

            try (CipherInputStream cis = new CipherInputStream(fis, cipher)) {
                byte[] buffer = new byte[chunkSize];
                int bytesRead;
                long totalBytesRead = 0;
                while ((bytesRead = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                    totalBytesRead += bytesRead;
                    listener.onProgress(totalBytesRead, ciphertextLength);
                }
            }
            listener.onSuccess("Decryption completed successfully.", destPath);
        } catch (Exception e) {
            listener.onError("Decryption failed.", e);
            throw e;
        }
    }
    
    private AlgorithmParameterSpec getAlgorithmParameterSpec(CryptoOptions options, byte[] iv) {
        CryptoOptions.CipherMode mode = options.getMode();

        if (mode.isAeadMode()) {
            if (mode == CryptoOptions.CipherMode.GCM || mode == CryptoOptions.CipherMode.CCM) {
                 return new GCMParameterSpec(options.getTagLength().getBits(), iv);
            }
        }
        
        if (mode == CryptoOptions.CipherMode.ECB || mode == CryptoOptions.CipherMode.WRAP) {
            return null;
        }

        return new IvParameterSpec(iv);
    }
}
