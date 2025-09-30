package com.example.myapplication.crypto;

import java.util.ArrayList;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Utility class for low-level OCB mode operations required for parallel processing.
 * This class handles the complex mathematics of calculating block offsets independently.
 */
public final class OcbUtil {

    private static final int BLOCK_SIZE_BYTES = 16; // AES block size

    // The irreducible polynomial for GF(2^128) used in OCB, x^128 + x^7 + x^2 + x + 1
    private static final int POLY = 0x87;

    /**
     * Implements the "double" operation in GF(2^128), which is multiplication by x.
     * @param block The block to be doubled.
     * @return The doubled block.
     */
    public static byte[] doubleVal(byte[] block) {
        byte[] result = new byte[BLOCK_SIZE_BYTES];
        int carry = (block[0] & 0xFF) >>> 7;
        for (int i = 0; i < BLOCK_SIZE_BYTES - 1; i++) {
            result[i] = (byte) ((block[i] << 1) | ((block[i + 1] & 0xFF) >>> 7));
        }
        result[BLOCK_SIZE_BYTES - 1] = (byte) (block[BLOCK_SIZE_BYTES - 1] << 1);
        if (carry != 0) {
            result[BLOCK_SIZE_BYTES - 1] ^= (byte) POLY;
        }
        return result;
    }

    /**
     * Pre-computes L_i = double(L_{i-1}) for i > 0, where L_0 = L.
     * This list is used to rapidly calculate any block offset.
     * @param L The base value L, calculated as Encrypt(Key, Zeros).
     * @param count The number of L values to pre-compute.
     * @return An ArrayList containing L_0, L_1, L_2, etc.
     */
    public static ArrayList<byte[]> precomputeL(byte[] L, int count) {
        ArrayList<byte[]> lValues = new ArrayList<>(count + 1);
        lValues.add(L);
        for (int i = 0; i < count; i++) {
            L = doubleVal(L);
            lValues.add(L);
        }
        return lValues;
    }

    /**
     * Calculates the offset for a given block index using the pre-computed L values.
     * Offset_i = L_{ntz(i)} xor Offset_{i-1}, where ntz is Number of Trailing Zeros.
     * This can be calculated directly as the XOR sum of L_{ntz(j)} for all j <= i where the j-th bit is 1.
     * @param lValues The pre-computed list of L_0, L_1, ...
     * @param blockIndex The absolute, 1-based index of the block.
     * @return The calculated offset for that block.
     */
    public static byte[] getOffset(ArrayList<byte[]> lValues, long blockIndex) {
        if (blockIndex == 0) {
            // This should not be called for block 0, but as a safeguard.
            return new byte[BLOCK_SIZE_BYTES];
        }
        long i = blockIndex;
        byte[] offset = new byte[BLOCK_SIZE_BYTES];
        while (i > 0) {
            int ntz = Long.numberOfTrailingZeros(i);
            xor(offset, lValues.get(ntz));
            i &= (i - 1); // clear the lowest set bit
        }
        return offset;
    }
    
    /**
     * Helper to XOR one byte array into another.
     * @param a The array to be modified (a = a XOR b).
     * @param b The array to XOR with.
     */
    public static void xor(byte[] a, byte[] b) {
        for (int i = 0; i < BLOCK_SIZE_BYTES; i++) {
            a[i] ^= b[i];
        }
    }
}
