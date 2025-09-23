package com.example.myapplication.crypto;

public class CryptoConfig {

    // Common properties for both Simple and Advanced modes
    private String password;

    // Advanced mode properties
    private boolean isAdvancedMode;
    private String algorithm;
    private int keyLength;
    private String blockMode;
    private String padding;
    private String kdf; // Key Derivation Function for symmetric
    private int threads;
    private String privateKey; // For asymmetric decryption

    // Enum for Simple Mode
    public enum SimpleMode {
        EFFICIENCY,
        PERFORMANCE
    }
    private SimpleMode simpleMode;


    // Getters and Setters for all properties

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isAdvancedMode() {
        return isAdvancedMode;
    }

    public void setAdvancedMode(boolean advancedMode) {
        isAdvancedMode = advancedMode;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public int getKeyLength() {
        return keyLength;
    }

    public void setKeyLength(int keyLength) {
        this.keyLength = keyLength;
    }

    public String getBlockMode() {
        return blockMode;
    }

    public void setBlockMode(String blockMode) {
        this.blockMode = blockMode;
    }

    public String getPadding() {
        return padding;
    }

    public void setPadding(String padding) {
        this.padding = padding;
    }

    public String getKdf() {
        return kdf;
    }

    public void setKdf(String kdf) {
        this.kdf = kdf;
    }

    public int getThreads() {
        return threads;
    }

    public void setThreads(int threads) {
        this.threads = threads;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public SimpleMode getSimpleMode() {
        return simpleMode;
    }

    public void setSimpleMode(SimpleMode simpleMode) {
        this.simpleMode = simpleMode;
    }
}
