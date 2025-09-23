package com.example.myapplication.crypto;

import org.spongycastle.bcpg.ArmoredOutputStream;
import org.spongycastle.bcpg.BCPGOutputStream;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openpgp.PGPCompressedDataGenerator;
import org.spongycastle.openpgp.PGPEncryptedDataGenerator;
import org.spongycastle.openpgp.PGPEncryptedDataList;
import org.spongycastle.openpgp.PGPException;
import org.spongycastle.openpgp.PGPLiteralData;
import org.spongycastle.openpgp.PGPLiteralDataGenerator;
import org.spongycastle.openpgp.PGPObjectFactory;
import org.spongycastle.openpgp.PGPOnePassSignature;
import org.spongycastle.openpgp.PGPOnePassSignatureList;
import org.spongycastle.openpgp.PGPPrivateKey;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPPublicKeyEncryptedData;
import org.spongycastle.openpgp.PGPPublicKeyRingCollection;
import org.spongycastle.openpgp.PGPSecretKey;
import org.spongycastle.openpgp.PGPSecretKeyRingCollection;
import org.spongycastle.openpgp.PGPSignature;
import org.spongycastle.openpgp.PGPSignatureGenerator;
import org.spongycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.spongycastle.openpgp.PGPUtil;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.spongycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.Date;
import java.util.Iterator;
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
    private static final String BC_PROVIDER = "BC";

    public CryptoManager(CryptoListener listener) {
        this.listener = listener;
    }

    // ... (existing AES encrypt/decrypt methods) ...

    public void encryptPGP(String publicKeyPath, String privateKeyPath, String passphrase, 
                         String inputFilePath, String outputFilePath, boolean sign) throws Exception {
        try (InputStream publicKeyIn = new BufferedInputStream(new FileInputStream(publicKeyPath));
             OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFilePath))) {

            PGPPublicKey pgpPublicKey = readPublicKey(publicKeyIn);
            if (pgpPublicKey == null) {
                throw new PGPException("Public key not found in key ring.");
            }

            PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(PGPEncryptedDataGenerator.CAST5)
                    .setWithIntegrityPacket(true)
                    .setSecureRandom(new SecureRandom())
                    .setProvider(BC_PROVIDER)
            );
            encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pgpPublicKey).setProvider(BC_PROVIDER));

            try (OutputStream encryptedOut = encryptedDataGenerator.open(out, new byte[1 << 16])) {
                PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedDataGenerator.ZIP);
                try (OutputStream compressedOut = compressedDataGenerator.open(encryptedOut, new byte[1 << 16])) {

                    PGPSignatureGenerator signatureGenerator = null;
                    if (sign) {
                        if (privateKeyPath == null || passphrase == null) {
                            throw new IllegalArgumentException("Private key and passphrase are required for signing.");
                        }
                        PGPSecretKey secretKey = readSecretKey(new FileInputStream(privateKeyPath));
                        PGPPrivateKey privateKey = secretKey.extractPrivateKey(
                            new JcePBESecretKeyDecryptorBuilder().setProvider(BC_PROVIDER).build(passphrase.toCharArray())
                        );
                        signatureGenerator = new PGPSignatureGenerator(
                            new JcaPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), PGPSignature.BINARY_DOCUMENT)
                                .setProvider(BC_PROVIDER)
                        );
                        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
                        
                        // Add user ID to signature
                        Iterator<String> userIDs = secretKey.getPublicKey().getUserIDs();
                        if (userIDs.hasNext()) {
                            PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();
                            subpacketGenerator.setSignerUserID(false, userIDs.next());
                            signatureGenerator.setHashedSubpackets(subpacketGenerator.generate());
                        }
                        signatureGenerator.generateOnePassVersion(false).encode(compressedOut);
                    }

                    PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
                    File inputFile = new File(inputFilePath);
                    try (OutputStream literalOut = literalDataGenerator.open(compressedOut, PGPLiteralData.BINARY, 
                            inputFile.getName(), new Date(), new byte[1 << 16])) {
                        try (FileInputStream fis = new FileInputStream(inputFile)) {
                            byte[] buffer = new byte[1 << 16];
                            int len;
                            long bytesProcessed = 0;
                            long totalBytes = inputFile.length();

                            while ((len = fis.read(buffer)) > 0) {
                                literalOut.write(buffer, 0, len);
                                if (sign && signatureGenerator != null) {
                                    signatureGenerator.update(buffer, 0, len);
                                }
                                bytesProcessed += len;
                                if(listener != null) {
                                    listener.onProgress((int)((bytesProcessed * 100) / totalBytes));
                                }
                            }
                        }
                    }
                    if (sign && signatureGenerator != null) {
                        signatureGenerator.generate().encode(compressedOut);
                    }
                }
            }
            if (listener != null) {
                listener.onSuccess("PGP Encryption Successful");
            }
        } catch (Exception e) {
            if (listener != null) {
                listener.onError("PGP Encryption failed: " + e.getMessage());
            }
            throw e;
        }
    }

    public static PGPPublicKey readPublicKey(InputStream input) throws Exception {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(input), null);
        Iterator<PGPPublicKey> keyIter = pgpPub.getKeyRings().next().getPublicKeys();
        while (keyIter.hasNext()) {
            PGPPublicKey key = keyIter.next();
            if (key.isEncryptionKey()) {
                return key;
            }
        }
        return null;
    }

    public static PGPSecretKey readSecretKey(InputStream input) throws Exception {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input), null);
        Iterator<PGPSecretKey> keyIter = pgpSec.getKeyRings().next().getSecretKeys();
        while (keyIter.hasNext()) {
            PGPSecretKey key = keyIter.next();
            if (key.isSigningKey()) {
                return key;
            }
        }
        return null;
    }

    // ... (rest of the class, including the AES methods)
}
