package com.example.myapplication.crypto;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Provides centralized information about supported cryptographic algorithms,
 * modes, key lengths, and paddings, especially those from Bouncy Castle.
 * This helps in dynamically populating UI elements and validating crypto parameters.
 */
public class CipherInfo {

    // Map: Cipher -> Supported Key Lengths (in bits)
    private static final Map<String, List<Integer>> supportedKeyLengths = new HashMap<>();

    // Lists of supported modes, paddings, and KDFs
    private static final List<String> supportedModes;
    private static final List<String> streamModes; // Modes that don't use padding
    private static final List<String> supportedPaddings;
    private static final List<String> supportedKdfs;

    static {
        // --- Initialize Supported Ciphers and Key Lengths ---
        // Values from Bouncy Castle specs.
        supportedKeyLengths.put("AES", Arrays.asList(256, 192, 128));
        supportedKeyLengths.put("Serpent", Arrays.asList(256, 192, 128));
        supportedKeyLengths.put("Twofish", Arrays.asList(256, 192, 128));
        supportedKeyLengths.put("Camellia", Arrays.asList(256, 192, 128));
        supportedKeyLengths.put("RC6", Arrays.asList(256, 192, 128));
        supportedKeyLengths.put("CAST6", Arrays.asList(256, 192, 128));
        supportedKeyLengths.put("SEED", Collections.singletonList(128));
        supportedKeyLengths.put("Noekeon", Collections.singletonList(128));
        supportedKeyLengths.put("ARIA", Arrays.asList(256, 192, 128));

        // --- Initialize Modes ---
        supportedModes = Arrays.asList("GCM", "CBC", "CTR", "CFB", "OFB");
        
        // Stream modes don't need padding. GCM is technically an AEAD mode but behaves like a stream cipher in this regard.
        streamModes = Arrays.asList("GCM", "CTR", "CFB", "OFB");

        // --- Initialize Paddings ---
        supportedPaddings = Arrays.asList("PKCS7Padding", "NoPadding");

        // --- Initialize KDFs ---
        supportedKdfs = Arrays.asList("PBKDF2WithHmacSHA256", "Scrypt");
    }

    /**
     * @return A sorted list of supported symmetric cipher algorithm names.
     */
    public static List<String> getSupportedCiphers() {
        List<String> ciphers = new ArrayList<>(supportedKeyLengths.keySet());
        Collections.sort(ciphers);
        return ciphers;
    }

    /**
     * Gets the valid key lengths for a given cipher algorithm.
     * @param cipher The name of the algorithm (e.g., "AES").
     * @return A list of integers representing key lengths in bits.
     */
    public static List<Integer> getValidKeyLengths(String cipher) {
        if (supportedKeyLengths.containsKey(cipher)) {
            return supportedKeyLengths.get(cipher);
        }
        return Collections.emptyList();
    }

    /**
     * @return A list of all supported block cipher modes.
     */
    public static List<String> getSupportedModes() {
        return new ArrayList<>(supportedModes);
    }

    /**
     * @return A list of all supported padding schemes.
     */
    public static List<String> getSupportedPaddings() {
        return new ArrayList<>(supportedPaddings);
    }
    
    /**
     * @return A list of all supported Key Derivation Functions.
     */
    public static List<String> getSupportedKdfs() {
        return new ArrayList<>(supportedKdfs);
    }

    /**
     * Checks if a given mode is a stream-like mode that does not require padding.
     * @param mode The mode to check (e.g., "GCM", "CTR").
     * @return true if the mode is a stream mode, false otherwise.
     */
    public static boolean isStreamMode(String mode) {
        return streamModes.contains(mode);
    }
}
