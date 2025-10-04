package com.example.myapplication.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.FileOutputStream;
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
        // Ensure the Bouncy Castle provider is added only once.
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Override
    public void encrypt(String sourcePath, String destPath, char[] password, CryptoOptions options, int chunkSize, CryptoListener listener) throws Exception {
        try (FileInputStream fis = new FileInputStream(sourcePath);
             FileOutputStream fos = new FileOutputStream(destPath)) {

            byte[] salt = KeyDerivation.generateSalt();
            SecretKey key = KeyDerivation.deriveKey(password, salt, options.getKdf(), options.getKeyLength());

            // Generate an IV/Nonce with the appropriate size for the selected mode.
            byte[] iv = generateIv(options.getMode(), options.getBlockSizeBits());

            FileHeader header = new FileHeader(options, iv, salt);
            header.writeTo(fos);

            String transformation = options.getTransformation();
            Cipher cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            
            AlgorithmParameterSpec spec = getAlgorithmParameterSpec(options, iv);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getEncoded(), options.getProtocol().name()), spec);

            // Add the header as Associated Authenticated Data (AAD) for AEAD ciphers.
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

            // If manual settings are provided, they override the header.
            if (manualOptions != null) {
                options = manualOptions;
            }

            SecretKey key = KeyDerivation.deriveKey(password, header.getSalt(), options.getKdf(), options.getKeyLength());
            byte[] iv = header.getIv();

            String transformation = options.getTransformation();
            Cipher cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            
            AlgorithmParameterSpec spec = getAlgorithmParameterSpec(options, iv);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getEncoded(), options.getProtocol().name()), spec);

            // The AAD must be provided for decryption exactly as it was for encryption.
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
    
    /**
     * Creates the appropriate AlgorithmParameterSpec based on the cipher mode.
     */
    private AlgorithmParameterSpec getAlgorithmParameterSpec(CryptoOptions options, byte[] iv) {
        CryptoOptions.CipherMode mode = options.getMode();

        if (mode.isAeadMode()) {
            return new GCMParameterSpec(options.getTagLength().getBits(), iv);
        }
        
        if (mode == CryptoOptions.CipherMode.ECB) {
            return null;
        }

        return new IvParameterSpec(iv);
    }
    
    /**
     * Generates an Initialization Vector (IV) or Nonce of the correct size for the chosen cipher mode.
     */
    private byte[] generateIv(CryptoOptions.CipherMode mode, int blockSizeBits) {
        byte[] iv;
        if (mode == CryptoOptions.CipherMode.GCM) {
            // A 12-byte (96-bit) IV is recommended for GCM for performance and security.
            iv = new byte[12];
        } else if (mode == CryptoOptions.CipherMode.CCM) {
            // For CCM, the nonce length must be between 7 and 13 bytes.
            iv = new byte[11];
        } else {
            // For other modes like CBC, CFB, OFB, CTR, EAX, and OCB,
            // the IV size must match the cipher's block size (16 bytes for AES).
            iv = new byte[blockSizeBits / 8];
        }
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
