package com.example.myapplication.crypto;

import org.json.JSONException;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;

/**
 * Represents the header of an encrypted file.
 * This header contains metadata (in JSON format) required to decrypt the file,
 * such as the cryptographic options used.
 * The on-disk format is: [4-byte header length] [UTF-8 JSON header]
 */
public class FileHeader {

    private final CryptoOptions options;

    public FileHeader(CryptoOptions options) {
        this.options = options;
    }

    public CryptoOptions getOptions() {
        return options;
    }

    /**
     * Serializes the header into a byte array for writing to a file.
     * @return A byte array representing the full header (length + JSON).
     * @throws JSONException If JSON serialization fails.
     */
    public byte[] toBytes() throws JSONException {
        JSONObject json = new JSONObject();
        json.put("protocol", options.getProtocol());
        json.put("keyLength", options.getKeyLength());
        json.put("mode", options.getMode());
        json.put("padding", options.getPadding());
        json.put("kdf", options.getKdf());
        // Chunk size and thread count are not needed for decryption but stored for completeness
        json.put("chunkSize", options.getChunkSize());
        json.put("threadCount", options.getThreadCount());

        byte[] jsonBytes = json.toString().getBytes(StandardCharsets.UTF_8);
        byte[] headerBytes = new byte[4 + jsonBytes.length];

        // Prepend the 4-byte length header
        System.arraycopy(intToBytes(jsonBytes.length), 0, headerBytes, 0, 4);
        System.arraycopy(jsonBytes, 0, headerBytes, 4, jsonBytes.length);

        return headerBytes;
    }

    /**
     * Parses a JSON string and creates a FileHeader object from it.
     * @param jsonString The JSON data read from the file.
     * @return A new FileHeader object.
     * @throws JSONException If parsing fails or keys are missing.
     */
    public static FileHeader fromJson(String jsonString) throws JSONException {
        JSONObject json = new JSONObject(jsonString);
        CryptoOptions options = new CryptoOptions(
            json.getString("protocol"),
            json.getInt("keyLength"),
            json.getString("mode"),
            json.getString("padding"),
            json.getString("kdf"),
            json.getInt("chunkSize"),
            json.getInt("threadCount")
        );
        return new FileHeader(options);
    }

    private static byte[] intToBytes(int i) {
        return new byte[] {
            (byte) (i >> 24),
            (byte) (i >> 16),
            (byte) (i >> 8),
            (byte) i
        };
    }
}
