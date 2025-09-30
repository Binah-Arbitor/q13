package com.example.myapplication.crypto;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public class CryptoOptions {

    private final CryptoProtocol protocol;
    private final KeyLength keyLength;
    private final int blockSizeBits;
    private final CipherMode mode;
    private final Padding padding;
    private final Kdf kdf;

    public CryptoOptions(CryptoProtocol protocol, KeyLength keyLength, int blockSizeBits, CipherMode mode, Padding padding, Kdf kdf) {
        this.protocol = protocol;
        this.keyLength = keyLength;
        this.blockSizeBits = blockSizeBits;
        this.mode = mode;
        this.padding = padding;
        this.kdf = kdf;
    }

    public static CryptoOptions getDefault() {
        return new CryptoOptions(CryptoProtocol.AES, KeyLength.BITS_256, 128, CipherMode.GCM, Padding.NoPadding, Kdf.PBKDF2WithHmacSHA256);
    }

    public String getTransformation() {
        return protocol.name() + "/" + mode.name() + "/" + padding.name();
    }

    // Getters
    public CryptoProtocol getProtocol() { return protocol; }
    public KeyLength getKeyLength() { return keyLength; }
    public int getBlockSizeBits() { return blockSizeBits; }
    public CipherMode getMode() { return mode; }
    public Padding getPadding() { return padding; }
    public Kdf getKdf() { return kdf; }

    @Override
    public String toString() {
        return String.format("%s-%d/%s/%s (KDF: %s)", protocol, keyLength.getBits(), mode, padding, kdf);
    }

    public enum CryptoProtocol {
        AES("AES", Arrays.asList(KeyLength.BITS_128, KeyLength.BITS_192, KeyLength.BITS_256),
            Arrays.asList(128), // AES block size is always 128 bits
            Arrays.asList(CipherMode.CBC, CipherMode.CFB, CipherMode.OFB, CipherMode.CTR, CipherMode.GCM, CipherMode.CCM, CipherMode.XTS)),
        BLOWFISH("Blowfish", Arrays.asList(KeyLength.BITS_128, KeyLength.BITS_256),
                 Arrays.asList(64), // Blowfish block size is 64 bits
                 Arrays.asList(CipherMode.CBC, CipherMode.CFB, CipherMode.OFB, CipherMode.CTR)),
        TWOFISH("Twofish", Arrays.asList(KeyLength.BITS_128, KeyLength.BITS_192, KeyLength.BITS_256),
                  Arrays.asList(128),
                  Arrays.asList(CipherMode.CBC)); // Example, can be extended

        private final String name;
        private final List<KeyLength> supportedKeyLengths;
        private final List<Integer> supportedBlockBits;
        private final List<CipherMode> supportedModes;

        CryptoProtocol(String name, List<KeyLength> keys, List<Integer> blocks, List<CipherMode> modes) {
            this.name = name;
            this.supportedKeyLengths = keys;
            this.supportedBlockBits = blocks;
            this.supportedModes = modes;
        }

        public boolean isXTS() {
            return this == AES; // Only AES supports XTS in this context
        }

        public Cipher getInitialisedCipher(int opmode, javax.crypto.SecretKey key, java.security.spec.AlgorithmParameterSpec spec) throws Exception {
            Cipher cipher = Cipher.getInstance(this.name() + "/" + spec.getClass().getSimpleName().replace("ParameterSpec","") + "/NoPadding"); // Simplified transformation string
            cipher.init(opmode, key, spec);
            return cipher;
        }

        public boolean isModeSupported(CipherMode mode) {
            return supportedModes.contains(mode);
        }
        
        @Override public String toString() { return name; }
        public List<KeyLength> getSupportedKeyLengths() { return supportedKeyLengths; }
        public List<Integer> getSupportedBlockBits() { return supportedBlockBits; }
        public List<CipherMode> getSupportedModes() { return supportedModes; }
    }

    public enum KeyLength {
        BITS_128(128), BITS_192(192), BITS_256(256), BITS_448(448); // 448 for Blowfish
        private final int bits;
        KeyLength(int bits) { this.bits = bits; }
        public int getBits() { return bits; }
        public int getBytes() { return bits / 8; }
        @Override public String toString() { return bits + "-bit"; }
    }

    public enum CipherMode {
        CBC, CFB, OFB, CTR, // Block cipher modes
        GCM, CCM, OCB, EAX, // Authenticated Encryption with Associated Data (AEAD) modes
        XTS; // Mode for disk encryption
        
        public boolean isStreamMode() {
             return this == CTR || this == GCM || this == CCM || this == OFB || this == CFB || this == OCB;
        }
    }

    public enum Padding {
        NoPadding, PKCS5Padding, ISO10126Padding;
    }

    public enum Kdf {
        PBKDF2WithHmacSHA1, PBKDF2WithHmacSHA256, PBKDF2WithHmacSHA512;
    }
}
