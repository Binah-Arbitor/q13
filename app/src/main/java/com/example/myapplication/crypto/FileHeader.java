package com.example.myapplication.crypto;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.Arrays;

public class FileHeader {
    private static final byte[] MAGIC_BYTES = new byte[]{(byte) 0x8A, (byte) 0xCE, (byte) 0xDA, (byte) 0xFE};
    private static final int HEADER_VERSION = 2; // Version bump for tag length

    private final CryptoOptions options;
    private final byte[] iv;
    private final byte[] salt;

    public FileHeader(CryptoOptions options, byte[] iv, byte[] salt) {
        this.options = options;
        this.iv = iv;
        this.salt = salt;
    }

    public CryptoOptions getOptions() { return options; }
    public byte[] getIv() { return iv; }
    public byte[] getSalt() { return salt; }

    public byte[] getAADBytes() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        dos.writeInt(HEADER_VERSION);
        dos.writeUTF(options.getProtocol().name());
        dos.writeInt(options.getKeyLength().getBits());
        dos.writeInt(options.getBlockSizeBits());
        dos.writeUTF(options.getMode().name());
        dos.writeUTF(options.getPadding().name());
        if (options.getTagLength() != null) {
            dos.writeInt(options.getTagLength().getBits());
        }
        dos.writeUTF(options.getKdf().name());
        dos.writeInt(iv.length);
        dos.write(iv);
        dos.writeInt(salt.length);
        dos.write(salt);
        dos.flush();

        return baos.toByteArray();
    }

    public void writeTo(OutputStream stream) throws IOException {
        stream.write(getHeaderBytes());
    }

    public void writeTo(RandomAccessFile file) throws IOException {
        file.write(getHeaderBytes());
    }

    public byte[] getHeaderBytes() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.write(MAGIC_BYTES);
        dos.writeInt(HEADER_VERSION);

        dos.writeUTF(options.getProtocol().name());
        dos.writeInt(options.getKeyLength().getBits());
        dos.writeInt(options.getBlockSizeBits());
        dos.writeUTF(options.getMode().name());
        dos.writeUTF(options.getPadding().name());
        
        // Write tag length ONLY if the mode is AEAD
        if (options.getMode().isAeadMode()) {
            dos.writeInt(options.getTagLength().getBits());
        }

        dos.writeUTF(options.getKdf().name());
        dos.writeInt(iv.length);
        dos.write(iv);
        dos.writeInt(salt.length);
        dos.write(salt);
        dos.flush();
        return baos.toByteArray();
    }

    public int getHeaderSize() throws IOException {
        return getHeaderBytes().length;
    }

    public static FileHeader fromStream(InputStream stream) throws IOException {
        DataInputStream dis = new DataInputStream(stream);

        byte[] magic = new byte[4];
        dis.readFully(magic);
        if (!Arrays.equals(magic, MAGIC_BYTES)) {
            throw new IOException("Not a valid encrypted file (magic bytes mismatch).");
        }

        int version = dis.readInt();
        if (version < 1) { // Allow older versions for now
            throw new IOException("Unsupported header version: " + version);
        }

        CryptoOptions.CryptoProtocol protocol = CryptoOptions.CryptoProtocol.valueOf(dis.readUTF());
        int keyLengthBits = dis.readInt();
        CryptoOptions.BlockSize blockSize = CryptoOptions.BlockSize.fromBits(dis.readInt());
        CryptoOptions.CipherMode mode = CryptoOptions.CipherMode.valueOf(dis.readUTF());
        CryptoOptions.Padding padding = CryptoOptions.Padding.valueOf(dis.readUTF());

        CryptoOptions.TagLength tagLength = null;
        if (version >= 2 && mode.isAeadMode()) {
            tagLength = CryptoOptions.TagLength.fromBits(dis.readInt());
        }

        CryptoOptions.Kdf kdf = CryptoOptions.Kdf.valueOf(dis.readUTF());

        CryptoOptions.KeyLength keyLength = Arrays.stream(CryptoOptions.KeyLength.values())
            .filter(kl -> kl.getBits() == keyLengthBits)
            .findFirst()
            .orElseThrow(() -> new IOException("Unsupported key length: " + keyLengthBits));

        CryptoOptions options = new CryptoOptions(protocol, keyLength, blockSize, mode, padding, tagLength, kdf);

        int ivLength = dis.readInt();
        byte[] iv = new byte[ivLength];
        dis.readFully(iv);

        int saltLength = dis.readInt();
        byte[] salt = new byte[saltLength];
        dis.readFully(salt);

        return new FileHeader(options, iv, salt);
    }
}
