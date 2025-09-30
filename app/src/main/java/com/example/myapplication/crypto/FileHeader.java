package com.example.myapplication.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class FileHeader implements Serializable {

    // "ENC" magic bytes + 2 bytes for version
    private static final byte[] MAGIC_BYTES = "ENC".getBytes(StandardCharsets.US_ASCII);
    private static final short VERSION = 1;
    public static final int MIN_HEADER_SIZE = MAGIC_BYTES.length + 2; // 5 bytes

    private final CryptoOptions options;
    private final byte[] salt;
    private final byte[] iv;

    public FileHeader(CryptoOptions options, byte[] salt, byte[] iv) {
        this.options = options;
        this.salt = salt;
        this.iv = iv;
    }

    public CryptoOptions getOptions() {
        return options;
    }

    public byte[] getSalt() {
        return salt;
    }

    public byte[] getIv() {
        return iv;
    }

    public byte[] getHeaderBytes() throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        
        // Magic bytes and version
        byteStream.write(MAGIC_BYTES);
        byteStream.write((byte) (VERSION >> 8));
        byteStream.write((byte) VERSION);

        // Write options as a string block
        writeBlock(byteStream, options.getProtocol().name().getBytes(StandardCharsets.UTF_8));
        writeBlock(byteStream, options.getKeyLength().name().getBytes(StandardCharsets.UTF_8));
        writeBlock(byteStream, String.valueOf(options.getBlockSizeBits()).getBytes(StandardCharsets.UTF_8));
        writeBlock(byteStream, options.getMode().name().getBytes(StandardCharsets.UTF_8));
        writeBlock(byteStream, options.getPadding().name().getBytes(StandardCharsets.UTF_8));
        writeBlock(byteStream, options.getKdf().name().getBytes(StandardCharsets.UTF_8));

        // Write salt and IV
        writeBlock(byteStream, salt);
        writeBlock(byteStream, iv);

        return byteStream.toByteArray();
    }

    private void writeBlock(ByteArrayOutputStream master, byte[] data) throws IOException {
        master.write(ByteBuffer.allocate(4).putInt(data.length).array());
        master.write(data);
    }

    public static FileHeader fromStream(InputStream is) throws IOException {
        byte[] magic = new byte[MAGIC_BYTES.length];
        if (is.read(magic) != magic.length || !java.util.Arrays.equals(magic, MAGIC_BYTES)) {
            throw new IOException("Not a valid encrypted file (magic bytes mismatch).");
        }

        byte[] versionBytes = new byte[2];
        if (is.read(versionBytes) != 2) throw new IOException("Could not read version.");
        short version = ByteBuffer.wrap(versionBytes).getShort();
        if (version != VERSION) throw new IOException("Unsupported file version.");

        try {
            CryptoOptions.CryptoProtocol protocol = CryptoOptions.CryptoProtocol.valueOf(new String(readBlock(is), StandardCharsets.UTF_8));
            CryptoOptions.KeyLength keyLength = CryptoOptions.KeyLength.valueOf(new String(readBlock(is), StandardCharsets.UTF_8));
            int blockSize = Integer.parseInt(new String(readBlock(is), StandardCharsets.UTF_8));
            CryptoOptions.CipherMode mode = CryptoOptions.CipherMode.valueOf(new String(readBlock(is), StandardCharsets.UTF_8));
            CryptoOptions.Padding padding = CryptoOptions.Padding.valueOf(new String(readBlock(is), StandardCharsets.UTF_8));
            CryptoOptions.Kdf kdf = CryptoOptions.Kdf.valueOf(new String(readBlock(is), StandardCharsets.UTF_8));
            
            CryptoOptions options = new CryptoOptions(protocol, keyLength, blockSize, mode, padding, kdf);

            byte[] salt = readBlock(is);
            byte[] iv = readBlock(is);

            return new FileHeader(options, salt, iv);
        } catch (Exception e) {
            throw new IOException("Failed to parse header fields.", e);
        }
    }

    private static byte[] readBlock(InputStream is) throws IOException {
        byte[] lengthBytes = new byte[4];
        if (is.read(lengthBytes) != 4) throw new IOException("Could not read block length.");
        int length = ByteBuffer.wrap(lengthBytes).getInt();
        if (length < 0 || length > 1024 * 1024) { // Sanity check
             throw new IOException("Invalid block length detected: " + length);
        }
        byte[] data = new byte[length];
        if (is.read(data) != length) throw new IOException("Unexpected end of stream while reading block.");
        return data;
    }
    
     public int getHeaderSize() throws IOException {
        return getHeaderBytes().length;
    }
}
