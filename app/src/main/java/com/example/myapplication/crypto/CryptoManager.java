package com.example.myapplication.crypto;

import org.spongycastle.bcpg.ArmoredOutputStream;
import org.spongycastle.bcpg.BCPGOutputStream;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openpgp.PGPCompressedData;
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
import org.spongycastle.openpgp.PGPSignatureList;
import org.spongycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.spongycastle.openpgp.PGPUtil;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.spongycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.spongycastle.util.io.Streams;

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
    private static final String ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_LENGTH = 256;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int KDF_SALT_LENGTH = 16;
    private static final int KDF_ITERATION_COUNT = 65536;

    public CryptoManager(CryptoListener listener) {
        this.listener = listener;
    }

    public void encrypt(String password, String inputFile, String outputFile) throws Exception {
        // ... (AES encryption implementation)
    }

    public void decrypt(String password, String inputFile, String outputFile) throws Exception {
        // ... (AES decryption implementation)
    }

    public void encryptPGP(String publicKeyPath, String privateKeyPath, String passphrase, 
                         String inputFilePath, String outputFilePath, boolean sign) throws Exception {
        // ... (PGP encryption implementation from before)
    }

    public void decryptPGP(String privateKeyPath, String passphrase, String inputFilePath, String outputFilePath, String signerPublicKeyPath) throws Exception {
        try (InputStream privateKeyIn = new BufferedInputStream(new FileInputStream(privateKeyPath));
             InputStream in = new BufferedInputStream(new FileInputStream(inputFilePath))) {

            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(privateKeyIn), null);

            InputStream decoderStream = PGPUtil.getDecoderStream(in);
            PGPObjectFactory pgpFact = new PGPObjectFactory(decoderStream, null);
            Object o = pgpFact.nextObject();

            PGPEncryptedDataList encList;
            if (o instanceof PGPEncryptedDataList) {
                encList = (PGPEncryptedDataList) o;
            } else {
                encList = (PGPEncryptedDataList) pgpFact.nextObject();
            }

            PGPPrivateKey privateKey = null;
            PGPPublicKeyEncryptedData pbe = null;
            Iterator<PGPPublicKeyEncryptedData> it = encList.getEncryptedDataObjects();

            while (privateKey == null && it.hasNext()) {
                pbe = it.next();
                PGPSecretKey secretKey = pgpSec.getSecretKey(pbe.getKeyID());
                if (secretKey != null) {
                    privateKey = secretKey.extractPrivateKey(
                        new JcePBESecretKeyDecryptorBuilder().setProvider(BC_PROVIDER).build(passphrase.toCharArray())
                    );
                }
            }

            if (privateKey == null) {
                throw new PGPException("Could not find private key to decrypt the message.");
            }

            try (InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(BC_PROVIDER).build(privateKey))) {
                PGPObjectFactory plainFact = new PGPObjectFactory(clear, null);
                Object message = plainFact.nextObject();

                if (message instanceof PGPCompressedData) {
                    PGPCompressedData cData = (PGPCompressedData) message;
                    plainFact = new PGPObjectFactory(cData.getDataStream(), null);
                    message = plainFact.nextObject();
                }

                PGPOnePassSignatureList onePassSignatureList = null;
                PGPSignatureList signatureList = null;
                PGPLiteralData ld = null;

                if (message instanceof PGPOnePassSignatureList) {
                    onePassSignatureList = (PGPOnePassSignatureList) message;
                    ld = (PGPLiteralData) plainFact.nextObject();
                } else {
                    ld = (PGPLiteralData) message;
                }

                try (InputStream unc = ld.getInputStream();
                     OutputStream fOut = new BufferedOutputStream(new FileOutputStream(outputFilePath))) {
                    
                    long totalBytes = ld.getModificationTime().getTime(); // Approximation
                    long bytesProcessed = 0;

                    int ch;
                    while ((ch = unc.read()) >= 0) {
                        fOut.write(ch);
                        bytesProcessed++;
                         if(listener != null) {
                             // This progress is not accurate, just an indicator
                            listener.onProgress((int)((bytesProcessed * 100) / (totalBytes > 0 ? totalBytes : 1)));
                        }
                    }
                }

                if (onePassSignatureList != null) {
                     signatureList = (PGPSignatureList) plainFact.nextObject();
                     PGPOnePassSignature ops = onePassSignatureList.get(0);
                     if (signerPublicKeyPath != null) {
                        PGPPublicKey publicKey = readPublicKey(new FileInputStream(signerPublicKeyPath));
                        ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider(BC_PROVIDER), publicKey);
                        
                        // Re-read the output file to verify signature
                        try(InputStream dataIn = new BufferedInputStream(new FileInputStream(outputFilePath))){
                            int ch;
                            while ((ch = dataIn.read()) >= 0) {
                                ops.update((byte) ch);
                            }
                        }

                        if (ops.verify(signatureList.get(0))) {
                            if (listener != null) listener.onSuccess("Decryption successful. Signature verified.");
                        } else {
                            if (listener != null) listener.onError("Decryption successful, but signature verification failed.");
                        }
                     } else {
                         if (listener != null) listener.onSuccess("Decryption successful. No public key provided to verify signature.");
                     }
                } else {
                    if (listener != null) listener.onSuccess("Decryption successful. No signature found to verify.");
                }
            }
        } catch (Exception e) {
            if (listener != null) {
                listener.onError("PGP Decryption failed: " + e.getMessage());
            }
            throw e;
        }
    }


    public static PGPPublicKey readPublicKey(InputStream input) throws Exception {
        // ... (implementation from before)
    }

    public static PGPSecretKey readSecretKey(InputStream input) throws Exception {
       // ... (implementation from before)
    }
}
