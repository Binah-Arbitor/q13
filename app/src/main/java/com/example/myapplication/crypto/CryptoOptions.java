package com.example.myapplication.crypto;

// A simple data class to hold all advanced encryption parameters.
public class CryptoOptions {
    private final String protocol;
    private final int keyLength;
    private final String mode;
    private final String padding;
    private final String kdf;
    private final int chunkSize;
    private final int threadCount;

    public CryptoOptions(String protocol, int keyLength, String mode, String padding, String kdf, int chunkSize, int threadCount) {
        this.protocol = protocol;
        this.keyLength = keyLength;
        this.mode = mode;
        this.padding = padding;
        this.kdf = kdf;
        this.chunkSize = chunkSize;
        this.threadCount = threadCount;
    }

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

    public String getCipherTransformation() {
        return protocol + "/" + mode + "/" + padding;
    }

    @Override
    public String toString() {
        return "CryptoOptions{" +
                "protocol='" + protocol + '\'' +
                ", keyLength=" + keyLength +
                ", mode='" + mode + '\'' +
                ", padding='" + padding + '\'' +
                ", kdf='" + kdf + '\'' +
                ", chunkSize=" + chunkSize +
                ", threadCount=" + threadCount +
                '}';
    }
}
