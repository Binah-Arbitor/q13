package com.example.myapplication.crypto;

import java.util.Arrays;
import java.util.List;

public class CryptoOptions {

    private final CryptoProtocol protocol;
    private final KeyLength keyLength;
    private final BlockSize blockSize;
    private final CipherMode mode;
    private final Padding padding;
    private final TagLength tagLength; // New field
    private final Kdf kdf;

    public CryptoOptions(CryptoProtocol protocol, KeyLength keyLength, BlockSize blockSize, CipherMode mode, Padding padding, TagLength tagLength, Kdf kdf) {
        this.protocol = protocol;
        this.keyLength = keyLength;
        this.blockSize = blockSize;
        this.mode = mode;
        this.padding = padding;
        this.tagLength = tagLength; // New field
        this.kdf = kdf;
    }

    public static CryptoOptions getDefault() {
        return new CryptoOptions(CryptoProtocol.AES, KeyLength.BITS_256, BlockSize.BITS_128, CipherMode.GCM, Padding.NoPadding, TagLength.BITS_128, Kdf.PBKDF2WithHmacSHA256);
    }

    public String getTransformation() {
        if (mode.isStreamMode() || padding == Padding.NoPadding) {
            return protocol.name() + "/" + mode.name();
        } else {
            return protocol.name() + "/" + mode.name() + "/" + padding.name();
        }
    }

    public boolean requiresAAD() {
        return mode.isAeadMode();
    }

    // Getters
    public CryptoProtocol getProtocol() { return protocol; }
    public KeyLength getKeyLength() { return keyLength; }
    public BlockSize getBlockSize() { return blockSize; }
    public int getBlockSizeBits() { return (blockSize != null) ? blockSize.getBits() : 0; }
    public CipherMode getMode() { return mode; }
    public Padding getPadding() { return padding; }
    public TagLength getTagLength() { return tagLength; } // New getter
    public Kdf getKdf() { return kdf; }

    @Override
    public String toString() {
        String format = (tagLength != null && mode.isAeadMode()) 
            ? "%s-%d/%s/%s (Tag: %d, KDF: %s)" 
            : "%s-%d/%s/%s (KDF: %s)";
        return String.format(format, protocol, keyLength.getBits(), mode, padding, 
            (tagLength != null && mode.isAeadMode()) ? tagLength.getBits() : kdf, 
            kdf);
    }

    // Enums ...
    public enum CryptoProtocol {
        AES("AES", Arrays.asList(KeyLength.BITS_128, KeyLength.BITS_192, KeyLength.BITS_256), Arrays.asList(BlockSize.BITS_128),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.GCM, CipherMode.CCM, CipherMode.WRAP, CipherMode.OCB, CipherMode.XTS)),
        ARIA("ARIA", Arrays.asList(KeyLength.BITS_128, KeyLength.BITS_192, KeyLength.BITS_256), Arrays.asList(BlockSize.BITS_128),
             Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.GCM, CipherMode.CCM, CipherMode.WRAP, CipherMode.OCB, CipherMode.XTS)),
        BLOWFISH("Blowfish", Arrays.asList(KeyLength.BITS_32, KeyLength.BITS_64, KeyLength.BITS_128, KeyLength.BITS_256, KeyLength.BITS_448), Arrays.asList(BlockSize.BITS_64),
                 Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB)),
        CAMELLIA("Camellia", Arrays.asList(KeyLength.BITS_128, KeyLength.BITS_192, KeyLength.BITS_256), Arrays.asList(BlockSize.BITS_128),
                   Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.GCM, CipherMode.CCM, CipherMode.WRAP, CipherMode.OCB, CipherMode.XTS)),
        CAST5("CAST5", Arrays.asList(KeyLength.BITS_40, KeyLength.BITS_64, KeyLength.BITS_128), Arrays.asList(BlockSize.BITS_64),
                Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB)),
        CAST6("CAST6", Arrays.asList(KeyLength.BITS_128, KeyLength.BITS_160, KeyLength.BITS_192, KeyLength.BITS_224, KeyLength.BITS_256), Arrays.asList(BlockSize.BITS_128),
                Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.OCB, CipherMode.XTS)),
        DES("DES", Arrays.asList(KeyLength.BITS_56), Arrays.asList(BlockSize.BITS_64),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.WRAP)),
        DESede("DESede", Arrays.asList(KeyLength.BITS_112, KeyLength.BITS_168), Arrays.asList(BlockSize.BITS_64),
                 Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.WRAP)),
        GOST28147("GOST28147", Arrays.asList(KeyLength.BITS_256), Arrays.asList(BlockSize.BITS_64),
                    Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CFB, CipherMode.WRAP)),
        IDEA("IDEA", Arrays.asList(KeyLength.BITS_128), Arrays.asList(BlockSize.BITS_64),
             Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB)),
        NOEKEON("Noekeon", Arrays.asList(KeyLength.BITS_128), Arrays.asList(BlockSize.BITS_128),
                  Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.GCM, CipherMode.CCM, CipherMode.WRAP, CipherMode.OCB, CipherMode.XTS)),
        RC2("RC2", Arrays.asList(KeyLength.BITS_8, KeyLength.BITS_64, KeyLength.BITS_128, KeyLength.BITS_256, KeyLength.BITS_1024), Arrays.asList(BlockSize.BITS_64),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.WRAP)),
        RC5("RC5", Arrays.asList(KeyLength.BITS_128, KeyLength.BITS_192, KeyLength.BITS_256), Arrays.asList(BlockSize.BITS_64),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB)),
        RC6("RC6", Arrays.asList(KeyLength.BITS_128, KeyLength.BITS_192, KeyLength.BITS_256), Arrays.asList(BlockSize.BITS_128),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.GCM, CipherMode.CCM, CipherMode.WRAP, CipherMode.OCB, CipherMode.XTS)),
        RIJNDAEL("Rijndael", Arrays.asList(KeyLength.BITS_128, KeyLength.BITS_160, KeyLength.BITS_192, KeyLength.BITS_224, KeyLength.BITS_256), Arrays.asList(BlockSize.BITS_128, BlockSize.BITS_160, BlockSize.BITS_192, BlockSize.BITS_224, BlockSize.BITS_256),
                   Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.OCB, CipherMode.XTS)),
        SEED("SEED", Arrays.asList(KeyLength.BITS_128), Arrays.asList(BlockSize.BITS_128),
             Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.GCM, CipherMode.CCM, CipherMode.WRAP, CipherMode.OCB, CipherMode.XTS)),
        SERPENT("Serpent", Arrays.asList(KeyLength.BITS_128, KeyLength.BITS_192, KeyLength.BITS_256), Arrays.asList(BlockSize.BITS_128),
                  Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.GCM, CipherMode.CCM, CipherMode.WRAP, CipherMode.OCB, CipherMode.XTS)),
        SKIPJACK("Skipjack", Arrays.asList(KeyLength.BITS_80), Arrays.asList(BlockSize.BITS_64),
                   Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB)),
        SM4("SM4", Arrays.asList(KeyLength.BITS_128), Arrays.asList(BlockSize.BITS_128),
            Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.GCM, CipherMode.CCM, CipherMode.WRAP, CipherMode.OCB, CipherMode.XTS)),
        THREEFISH("Threefish", Arrays.asList(KeyLength.BITS_256, KeyLength.BITS_512, KeyLength.BITS_1024), Arrays.asList(BlockSize.BITS_256, BlockSize.BITS_512, BlockSize.BITS_1024),
                    Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB)),
        TWOFISH("Twofish", Arrays.asList(KeyLength.BITS_128, KeyLength.BITS_192, KeyLength.BITS_256), Arrays.asList(BlockSize.BITS_128),
                  Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB, CipherMode.WRAP, CipherMode.OCB, CipherMode.XTS)),
        XTEA("XTEA", Arrays.asList(KeyLength.BITS_128), Arrays.asList(BlockSize.BITS_64),
             Arrays.asList(CipherMode.ECB, CipherMode.CBC, CipherMode.CTR, CipherMode.OFB, CipherMode.CFB));

        private final String name;
        private final List<KeyLength> supportedKeyLengths;
        private final List<BlockSize> supportedBlockSizes;
        private final List<CipherMode> supportedModes;

        CryptoProtocol(String name, List<KeyLength> keys, List<BlockSize> blocks, List<CipherMode> modes) {
            this.name = name;
            this.supportedKeyLengths = keys;
            this.supportedBlockSizes = blocks;
            this.supportedModes = modes;
        }

        public boolean isXTS() {
            return this == AES || this == ARIA || this == CAMELLIA || this == CAST6 || this == NOEKEON || this == RC6 || this == RIJNDAEL || this == SEED || this == SERPENT || this == SM4 || this == TWOFISH;
        }

        public boolean isModeSupported(CipherMode mode) {
            return supportedModes.contains(mode);
        }

        @Override public String toString() { return name; }
        public List<KeyLength> getSupportedKeyLengths() { return supportedKeyLengths; }
        public List<BlockSize> getSupportedBlockSizes() { return supportedBlockSizes; }
        public List<CipherMode> getSupportedModes() { return supportedModes; }
    }

    public enum KeyLength {
        BITS_8(8), BITS_32(32), BITS_40(40), BITS_56(56), BITS_64(64), BITS_80(80), BITS_112(112),
        BITS_128(128), BITS_160(160), BITS_168(168), BITS_192(192), BITS_224(224), BITS_256(256),
        BITS_448(448), BITS_512(512), BITS_1024(1024);

        private final int bits;
        KeyLength(int bits) { this.bits = bits; }
        public int getBits() { return bits; }
        public int getBytes() { return bits / 8; }
        @Override public String toString() { return bits + "-bit"; }
    }
    
    public enum BlockSize {
        BITS_64(64), BITS_128(128), BITS_160(160), BITS_192(192), BITS_224(224),
        BITS_256(256), BITS_512(512), BITS_1024(1024);
        
        private final int bits;
        BlockSize(int bits) { this.bits = bits; }
        public int getBits() { return bits; }
        public int getBytes() { return bits / 8; }
        @Override public String toString() { return bits + "-bit"; }

        public static BlockSize fromBits(int bits) {
            for (BlockSize b : values()) {
                if (b.bits == bits) {
                    return b;
                }
            }
            return null;
        }
    }

    public enum CipherMode {
        ECB, CBC, CTR, OFB, CFB, WRAP, 
        GCM, CCM, OCB, EAX,          
        XTS;                         

        public boolean isStreamMode() {
            return this == CTR || this == OFB || this == CFB || isAeadMode();
        }
        
        public boolean isAeadMode() {
            return this == GCM || this == CCM || this == OCB || this == EAX;
        }
    }
    
    // New Enum for Tag Length
    public enum TagLength {
        BITS_128(128), BITS_120(120), BITS_112(112), BITS_104(104), BITS_96(96);

        private final int bits;
        TagLength(int bits) { this.bits = bits; }
        public int getBits() { return bits; }
        @Override public String toString() { return bits + "-bit"; }

        public static TagLength fromBits(int bits) {
            for (TagLength tl : values()) {
                if (tl.bits == bits) {
                    return tl;
                }
            }
            return null;
        }
    }

    public enum Padding {
        NoPadding, PKCS5Padding, ISO10126Padding;
    }

    public enum Kdf {
        PBKDF2WithHmacSHA1, PBKDF2WithHmacSHA256, PBKDF2WithHmacSHA512;
    }
}
