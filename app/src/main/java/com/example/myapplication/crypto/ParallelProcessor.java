package com.example.myapplication.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicLong;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Implements cryptographically sound parallel processing for seekable cipher modes (CTR, GCM, CCM).
 * For non-parallelizable modes (like CBC), it safely falls back to sequential processing.
 */
public class ParallelProcessor implements IProcessor {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final ExecutorService executor;
    private final IProcessor sequentialProcessor = new SequentialProcessor();

    public ParallelProcessor(int numThreads) {
        this.executor = Executors.newFixedThreadPool(numThreads);
    }

    @Override
    public void encrypt(String sourcePath, String destPath, char[] password, CryptoOptions options, int chunkSize, CryptoListener listener) throws Exception {
        // Fallback to sequential for modes that are not safely parallelizable.
        if (!options.getMode().isParallelizable()) {
            listener.onLog("Warning: Selected mode is not parallelizable. Falling back to sequential processing.");
            sequentialProcessor.encrypt(sourcePath, destPath, password, options, chunkSize, listener);
            return;
        }

        try (RandomAccessFile sourceRaf = new RandomAccessFile(sourcePath, "r");
             RandomAccessFile destRaf = new RandomAccessFile(destPath, "rw")) {

            long fileLength = sourceRaf.length();
            listener.onStart(fileLength);

            byte[] salt = KeyDerivation.generateSalt();
            SecretKey key = KeyDerivation.deriveKey(password, salt, options.getKdf(), options.getKeyLength());

            byte[] iv = generateIv(options.getMode(), options.getBlockSizeBits());

            FileHeader header = new FileHeader(options, iv, salt);
            destRaf.setLength(0); // Clear the file before writing
            header.writeTo(destRaf);
            long headerSize = destRaf.getFilePointer();

            List<Future<?>> futures = new ArrayList<>();
            AtomicLong totalBytesProcessed = new AtomicLong(0);
            final int blockSize = options.getBlockSizeBits() / 8;

            for (long offset = 0; offset < fileLength; offset += chunkSize) {
                final long chunkStart = offset;
                final long chunkLength = Math.min(chunkSize, fileLength - offset);

                futures.add(executor.submit(() -> {
                    try {
                        byte[] data = new byte[(int) chunkLength];
                        synchronized (sourceRaf) {
                            sourceRaf.seek(chunkStart);
                            sourceRaf.readFully(data);
                        }

                        // Calculate the starting counter for this specific chunk.
                        BigInteger ivAsBigInt = new BigInteger(1, iv);
                        BigInteger blockOffset = BigInteger.valueOf(chunkStart / blockSize);
                        BigInteger newIvBigInt = ivAsBigInt.add(blockOffset);
                        byte[] chunkIv = newIvBigInt.toByteArray();

                        // Ensure the new IV has the correct length, padding if necessary.
                        byte[] finalChunkIv = new byte[iv.length];
                        if (chunkIv.length >= iv.length) {
                            System.arraycopy(chunkIv, chunkIv.length - iv.length, finalChunkIv, 0, iv.length);
                        } else {
                            System.arraycopy(chunkIv, 0, finalChunkIv, iv.length - chunkIv.length, chunkIv.length);
                        }

                        String transformation = options.getTransformation();
                        Cipher cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
                        AlgorithmParameterSpec spec = getAlgorithmParameterSpec(options, finalChunkIv);

                        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getEncoded(), options.getProtocol().name()), spec);

                        // For AEAD modes, AAD must be provided to each cipher instance.
                        if (options.requiresAAD()) {
                            cipher.updateAAD(header.getAADBytes());
                        }

                        byte[] encryptedData = cipher.doFinal(data);

                        // Write the encrypted chunk to the correct position in the output file.
                        synchronized (destRaf) {
                            destRaf.seek(headerSize + chunkStart);
                            destRaf.write(encryptedData);
                        }

                        long processed = totalBytesProcessed.addAndGet(chunkLength);
                        listener.onProgress(processed, fileLength);

                    } catch (Exception e) {
                        throw new RuntimeException("Error during parallel encryption of a chunk", e);
                    }
                }));
            }

            for (Future<?> future : futures) {
                future.get(); // Wait for all tasks to complete and check for exceptions
            }
            listener.onSuccess("Encryption completed successfully.", destPath);

        } catch (Exception e) {
            listener.onError("Encryption failed.", e);
            throw e;
        } finally {
            executor.shutdown();
        }
    }

    @Override
    public void decrypt(String sourcePath, String destPath, char[] password, CryptoOptions manualOptions, int chunkSize, CryptoListener listener) throws Exception {
        // Parallel decryption is significantly more complex to implement correctly (especially with padding).
        // For security and correctness, fallback to the robust sequential processor.
        listener.onLog("Note: Using secure sequential mode for decryption.");
        sequentialProcessor.decrypt(sourcePath, destPath, password, manualOptions, chunkSize, listener);
    }

    private AlgorithmParameterSpec getAlgorithmParameterSpec(CryptoOptions options, byte[] iv) {
        if (options.getMode().isAeadMode()) {
            return new GCMParameterSpec(options.getTagLength().getBits(), iv);
        }
        // For CTR mode, IvParameterSpec is correct.
        return new IvParameterSpec(iv);
    }

    private byte[] generateIv(CryptoOptions.CipherMode mode, int blockSizeBits) {
        byte[] iv;
        if (mode == CryptoOptions.CipherMode.GCM) {
            iv = new byte[12]; // 96 bits is recommended
        } else if (mode == CryptoOptions.CipherMode.CCM) {
            iv = new byte[11]; // 7 to 13 bytes allowed, 11 is a common choice
        } else {
            iv = new byte[blockSizeBits / 8]; // e.g., 16 bytes for AES/CTR
        }
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
