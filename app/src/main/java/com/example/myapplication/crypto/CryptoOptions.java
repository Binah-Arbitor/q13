package com.example.myapplication.crypto;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class CryptoOptions implements Serializable {
    private static final long serialVersionUID = 3L; // Version update for block size addition

    private final CryptoProtocol protocol;
    private final KeyLength keyLength;
    private final int blockBitSize; // Newly added field
    private final CipherMode mode;
    private final Padding padding;
    private final Kdf kdf;

    public enum CryptoProtocol {
        // Name, Supported Keys, Supported Block Sizes (bits), Supported Modes
        AES("AES", Collections.singletonList(128), Arrays.asList(KeyLength.L128, KeyLength.L192, KeyLength.L256),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.GCM, CipherMode.CCM, CipherMode.OCB, CipherMode.XTS, CipherMode.KEY_WRAP)),
        ARIA("ARIA", Collections.singletonList(128), Arrays.asList(KeyLength.L128, KeyLength.L192, KeyLength.L256),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.GCM, CipherMode.CCM, CipherMode.OCB, CipherMode.XTS)),
        BLOWFISH("Blowfish", Collections.singletonList(64), Arrays.asList(KeyLength.L128, KeyLength.L256, KeyLength.L448),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB)),
        CAMELLIA("Camellia", Collections.singletonList(128), Arrays.asList(KeyLength.L128, KeyLength.L192, KeyLength.L256),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.GCM, CipherMode.CCM, CipherMode.OCB, CipherMode.XTS, CipherMode.KEY_WRAP)),
        CAST5("CAST5", Collections.singletonList(64), Arrays.asList(KeyLength.L40, KeyLength.L128),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB)),
        CAST6("CAST6", Collections.singletonList(128), Arrays.asList(KeyLength.L128, KeyLength.L160, KeyLength.L192, KeyLength.L224, KeyLength.L256),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.OCB, CipherMode.XTS)),
        DES("DES", Collections.singletonList(64), Arrays.asList(KeyLength.L56),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.KEY_WRAP)),
        DESEDE("DESede", Collections.singletonList(64), Arrays.asList(KeyLength.L112, KeyLength.L168),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.KEY_WRAP)),
        GOST28147("GOST28147", Collections.singletonList(64), Arrays.asList(KeyLength.L256),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CFB, CipherMode.KEY_WRAP)),
        IDEA("IDEA", Collections.singletonList(64), Arrays.asList(KeyLength.L128),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB)),
        NOEKEON("Noekeon", Collections.singletonList(128), Arrays.asList(KeyLength.L128),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.GCM, CipherMode.CCM, CipherMode.OCB, CipherMode.XTS, CipherMode.KEY_WRAP)),
        RC2("RC2", Collections.singletonList(64), Arrays.asList(KeyLength.L128, KeyLength.L256, KeyLength.L1024),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.KEY_WRAP)),
        RC5("RC5", Collections.singletonList(64), Arrays.asList(KeyLength.L128, KeyLength.L256, KeyLength.L512),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB)),
        RC6("RC6", Collections.singletonList(128), Arrays.asList(KeyLength.L128, KeyLength.L192, KeyLength.L256),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.GCM, CipherMode.CCM, CipherMode.OCB, CipherMode.XTS, CipherMode.KEY_WRAP)),
        RIJNDAEL("Rijndael", Arrays.asList(128, 160, 192, 224, 256), Arrays.asList(KeyLength.L128, KeyLength.L160, KeyLength.L192, KeyLength.L224, KeyLength.L256),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.OCB, CipherMode.XTS)),
        SEED("SEED", Collections.singletonList(128), Arrays.asList(KeyLength.L128),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.GCM, CipherMode.CCM, CipherMode.OCB, CipherMode.XTS, CipherMode.KEY_WRAP)),
        SERPENT("Serpent", Collections.singletonList(128), Arrays.asList(KeyLength.L128, KeyLength.L192, KeyLength.L256),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.GCM, CipherMode.CCM, CipherMode.OCB, CipherMode.XTS, CipherMode.KEY_WRAP)),
        SKIPJACK("Skipjack", Collections.singletonList(64), Arrays.asList(KeyLength.L80),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB)),
        SM4("SM4", Collections.singletonList(128), Arrays.asList(KeyLength.L128),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.GCM, CipherMode.CCM, CipherMode.OCB, CipherMode.XTS, CipherMode.KEY_WRAP)),
        THREEFISH_256("Threefish-256", Collections.singletonList(256), Arrays.asList(KeyLength.L256), Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB)),
        THREEFISH_512("Threefish-512", Collections.singletonList(512), Arrays.asList(KeyLength.L512), Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB)),
        THREEFISH_1024("Threefish-1024", Collections.singletonList(1024), Arrays.asList(KeyLength.L1024), Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB)),
        TWOFISH("Twofish", Collections.singletonList(128), Arrays.asList(KeyLength.L128, KeyLength.L192, KeyLength.L256),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.OCB, CipherMode.XTS, CipherMode.KEY_WRAP)),
        XTEA("XTEA", Collections.singletonList(64), Arrays.asList(KeyLength.L128), 
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB));

        private final String name;
        private final List<Integer> supportedBlockBits;
        private final List<KeyLength> supportedKeyLengths;
        private final List<CipherMode> supportedModes;

        CryptoProtocol(String name, List<Integer> supportedBlockBits, List<KeyLength> supportedKeyLengths, List<CipherMode> supportedModes) {
            this.name = name;
            this.supportedBlockBits = supportedBlockBits;
            this.supportedKeyLengths = supportedKeyLengths;
            this.supportedModes = supportedModes;
        }

        public String getName() { return name; }
        public List<Integer> getSupportedBlockBits() { return supportedBlockBits; }
        public List<KeyLength> getSupportedKeyLengths() { return supportedKeyLengths; }
        public List<CipherMode> getSupportedModes() { return supportedModes; }
    }

    public enum KeyLength { L40(40), L56(56), L80(80), L112(112), L128(128), L160(160), L168(168), L192(192), L224(224), L256(256), L448(448), L512(512), L1024(1024); 
        private final int length; KeyLength(int length) { this.length = length; } public int getLength() { return length; } }

    public enum CipherMode { ECB, CBC, CTR, OFB, CFB, GCM, CCM, OCB, XTS, KEY_WRAP; }

    public enum Padding { PKCS5Padding, PKCS7Padding, NoPadding; }

    public enum Kdf { PBKDF2WithHmacSHA256; }

    public CryptoOptions(CryptoProtocol protocol, KeyLength keyLength, int blockBitSize, CipherMode mode, Padding padding, Kdf kdf) {
        if (!protocol.getSupportedKeyLengths().contains(keyLength)) {
            throw new IllegalArgumentException("Key length " + keyLength.getLength() + " is not supported by " + protocol.getName());
        }
        if (!protocol.getSupportedBlockBits().contains(blockBitSize)) {
            throw new IllegalArgumentException("Block size " + blockBitSize + " is not supported by " + protocol.getName());
        }
        if (!protocol.getSupportedModes().contains(mode)) {
            throw new IllegalArgumentException("Cipher mode " + mode.name() + " is not supported by " + protocol.getName());
        }
        if (mode == CipherMode.XTS && blockBitSize != 128) {
            throw new IllegalArgumentException("XTS mode is only supported for 128-bit block ciphers, but " + protocol.getName() + " with block size " + blockBitSize + " was chosen.");
        }

        this.protocol = protocol;
        this.keyLength = keyLength;
        this.blockBitSize = blockBitSize;
        this.mode = mode;
        this.padding = padding;
        this.kdf = kdf;
    }

    public static CryptoOptions getDefault() {
        return new CryptoOptions(CryptoProtocol.AES, KeyLength.L256, 128, CipherMode.GCM, Padding.NoPadding, Kdf.PBKDF2WithHmacSHA256);
    }

    public String getCipherTransformation() {
        return protocol.getName() + "/" + mode.name() + "/" + padding.name();
    }

    public boolean isParallelizable() {
        return mode == CipherMode.CTR || mode == CipherMode.OCB || mode == CipherMode.ECB || mode == CipherMode.XTS;
    }

    public int getIvLengthBytes() {
        return this.blockBitSize / 8;
    }
    
    // Standard Getters
    public CryptoProtocol getProtocol() { return protocol; }
    public KeyLength getKeyLengthEnum() { return keyLength; }
    public int getKeyLength() { return keyLength.getLength(); }
    public int getBlockBitSize() { return blockBitSize; }
    public CipherMode getMode() { return mode; }
    public Padding getPadding() { return padding; }
    public Kdf getKdfEnum() { return kdf; }
    public String getKdf() { return kdf.name(); }
}
