package com.example.myapplication.crypto;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Provides centralized information about supported cryptographic algorithms,
 * modes, key lengths, and paddings, especially those from Bouncy Castle.
 * This helps in dynamically populating UI elements and validating crypto parameters.
 */
public class CipherInfo {

    // Map: Cipher -> Supported Key Lengths (in bits)
    private static final Map<String, List<Integer>> supportedKeyLengths = new HashMap<>();

    // Map: Cipher -> Supported Modes
    private static final Map<String, List<String>> protocolToModes = new HashMap<>();

    // Lists of supported modes, paddings, and KDFs
    private static final List<String> streamModes; // Modes that don't use padding
    private static final List<String> supportedPaddings;
    private static final List<String> supportedKdfs;

    static {
        // --- Initialize Supported Ciphers and Key Lengths ---
        supportedKeyLengths.put("AES", Arrays.asList(256, 192, 128));
        supportedKeyLengths.put("Serpent", Arrays.asList(256, 192, 128));
        supportedKeyLengths.put("Twofish", Arrays.asList(256, 192, 128));
        supportedKeyLengths.put("Camellia", Arrays.asList(256, 192, 128));
        supportedKeyLengths.put("DESede", Arrays.asList(192, 128)); // 3-key and 2-key TripleDES
        supportedKeyLengths.put("RC6", Arrays.asList(256, 192, 128));
        supportedKeyLengths.put("CAST6", Arrays.asList(256, 192, 128));
        supportedKeyLengths.put("SEED", Collections.singletonList(128));
        supportedKeyLengths.put("Noekeon", Collections.singletonList(128));
        supportedKeyLengths.put("ARIA", Arrays.asList(256, 192, 128));

        // --- Initialize Modes ---
        List<String> commonBlockModes = Arrays.asList("CBC", "CTR", "CFB", "OFB");
        List<String> aeadModes = Arrays.asList("GCM", "CCM", "EAX"); // Modes that provide authentication

        List<String> aesModes = new ArrayList<>();
        aesModes.addAll(aeadModes);
        aesModes.addAll(commonBlockModes);
        Collections.sort(aesModes);
        protocolToModes.put("AES", aesModes);
        protocolToModes.put("Camellia", aesModes);
        protocolToModes.put("Serpent", aesModes);
        protocolToModes.put("Twofish", aesModes);
        protocolToModes.put("ARIA", aesModes);

        // Older/other ciphers generally don't support modern AEAD modes like GCM in standard implementations
        protocolToModes.put("DESede", commonBlockModes);
        protocolToModes.put("RC6", commonBlockModes);
        protocolToModes.put("CAST6", commonBlockModes);
        protocolToModes.put("SEED", commonBlockModes);
        protocolToModes.put("Noekeon", commonBlockModes);

        // Stream modes don't need padding. GCM is technically an AEAD mode but behaves like a stream cipher in this regard.
        streamModes = Arrays.asList("GCM", "CTR", "CFB", "OFB", "CCM", "EAX");

        // --- Initialize Paddings (Expanded List) ---
        supportedPaddings = Arrays.asList(
            "PKCS7Padding",
            "ISO10126-2Padding",
            "X923Padding",
            "ISO7816-4Padding",
            "ZeroBytePadding",
            "TBCPadding" // Trailing-Bit-Compliment Padding
        );

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
        return supportedKeyLengths.getOrDefault(cipher, Collections.emptyList());
    }

    /**
     * Gets the supported block cipher modes for a given cipher protocol.
     * @param protocol The cipher protocol (e.g., "AES").
     * @return A list of supported modes for that protocol.
     */
    public static List<String> getSupportedModes(String protocol) {
        return protocolToModes.getOrDefault(protocol, Collections.emptyList());
    }

    /**
     * Gets a comprehensive list of all unique supported modes across all protocols.
     * @return A sorted list of unique mode names.
     */
    public static List<String> getAllSupportedModes() {
        Set<String> allModes = new LinkedHashSet<>();
        for (List<String> modes : protocolToModes.values()) {
            allModes.addAll(modes);
        }
        List<String> sortedModes = new ArrayList<>(allModes);
        Collections.sort(sortedModes);
        return sortedModes;
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
