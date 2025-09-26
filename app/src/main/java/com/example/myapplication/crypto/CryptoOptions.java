package com.example.myapplication.crypto;

/**
 * A simple data class to hold all advanced encryption parameters.
 */
public class CryptoOptions {
    private final String protocol;
    private final int keyLength;
    private final String mode;
    private final String padding;
    private final String kdf;
    private final int chunkSize;
    private final int threadCount;

    // Standard IV lengths (in bytes)
    private static final int GCM_IV_LENGTH = 12; // 96 bits is recommended for GCM
    private static final int DEFAULT_IV_LENGTH = 16; // 128 bits is common for AES block modes

    public CryptoOptions(String protocol, int keyLength, String mode, String padding, String kdf, int chunkSize, int threadCount) {
        this.protocol = protocol;
        this.keyLength = keyLength;
        this.mode = mode;
        this.padding = padding;
        this.kdf = kdf;
        this.chunkSize = chunkSize;
        this.threadCount = threadCount;
    }

    // --- Getters ---

    public String getProtocol() {
        return protocol;
    }

    public int getKeyLength() {
        return keyLength;
    }

    public String getMode() {
        return mode;
    }

    public String getPadding() {
        return padding;
    }

    public String getKdf() {
        return kdf;
    }

    public int getChunkSize() {
        return chunkSize;
    }

    public int getThreadCount() {
        return threadCount;
    }

    /**
     * Returns the full transformation string for initializing a Cipher instance.
     * @return The transformation string, e.g., "AES/GCM/NoPadding".
     */
    public String getCipherTransformation() {
        return protocol + "/" + mode + "/" + padding;
    }

    /**
     * Determines the appropriate IV length based on the selected cipher mode.
     * GCM mode has a standard recommended IV size of 12 bytes (96 bits) for performance.
     * Most other block cipher modes use an IV equal to the block size (16 bytes for AES).
     * @return The required IV length in bytes.
     */
    public int getIvLengthBytes() {
        if ("GCM".equalsIgnoreCase(mode)) {
            return GCM_IV_LENGTH;
        }
        return DEFAULT_IV_LENGTH;
    }

    @Override
    public String toString() {
        return "CryptoOptions{" +
                "protocol='" + protocol + '\'' +
                ", keyLength=" + keyLength +
                ", mode='" + mode + '\'' +
                ", padding='" + padding + '\'' +
                ", kdf='" + kdf + '\'' +
                ", ivLength=" + getIvLengthBytes() + // Added for logging
                ", chunkSize=" + chunkSize +
                ", threadCount=" + threadCount +
                '}';
    }
}
