package com.example.myapplication.crypto;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;

public class FileHeader implements Serializable {
    private static final long serialVersionUID = 3L;

    private final CryptoOptions options;
    private final byte[] salt;
    private final byte[] iv;

    private transient int headerSize = 0;

    public FileHeader(CryptoOptions options, byte[] salt, byte[] iv) {
        this.options = options;
        this.salt = salt;
        this.iv = iv;
    }

    public int writeTo(OutputStream os) throws IOException {
        try (DataOutputStream dos = new DataOutputStream(os)) {
            dos.writeLong(serialVersionUID);
            try (ObjectOutputStream oos = new ObjectOutputStream(dos)) {
                oos.writeObject(options);
            }
            dos.writeInt(salt.length);
            dos.write(salt);
            dos.writeInt(iv.length);
            dos.write(iv);
            dos.flush();
            this.headerSize = dos.size();
        }
        return this.headerSize;
    }

    public static FileHeader readFrom(InputStream is) throws IOException, ClassNotFoundException {
        DataInputStream dis = new DataInputStream(is);
        long fileVersion = dis.readLong();
        if (fileVersion != serialVersionUID) {
            throw new IOException("Incompatible file header version. Expected " + serialVersionUID + ", but found " + fileVersion);
        }

        ObjectInputStream ois = new ObjectInputStream(dis);
        CryptoOptions options = (CryptoOptions) ois.readObject();

        int saltLength = dis.readInt();
        byte[] salt = new byte[saltLength];
        dis.readFully(salt);

        int ivLength = dis.readInt();
        byte[] iv = new byte[ivLength];
        dis.readFully(iv);

        FileHeader header = new FileHeader(options, salt, iv);
        // The size isn't directly available here, but could be calculated if needed.
        return header;
    }

    /**
     * Peeks into an encrypted file to read just the CryptoOptions from the header.
     * This is useful for the CryptoManager to decide which decryption strategy to use
     * without reading the entire file or header.
     *
     * @param filePath The path to the encrypted file.
     * @return The CryptoOptions stored in the file's header.
     * @throws IOException if an I/O error occurs.
     * @throws ClassNotFoundException if the CryptoOptions class cannot be found.
     */
    public static CryptoOptions peekOptions(String filePath) throws IOException, ClassNotFoundException {
        try (FileInputStream fis = new FileInputStream(filePath);
             DataInputStream dis = new DataInputStream(fis)) {

            long fileVersion = dis.readLong();
            if (fileVersion != serialVersionUID) {
                throw new IOException("Cannot peek options: Incompatible file header version. Expected "
                        + serialVersionUID + ", but found " + fileVersion);
            }

            // ObjectInputStream will read from the DataInputStream until the object is fully deserialized.
            // It's crucial that the underlying stream (dis/fis) is not closed prematurely.
            try (ObjectInputStream ois = new ObjectInputStream(dis)) {
                 return (CryptoOptions) ois.readObject();
            }
        }
    }

    // Standard Getters
    public CryptoOptions getOptions() {
        return options;
    }

    public byte[] getSalt() {
        return salt;
    }

    public byte[] getIv() {
        return iv;
    }

    public int getHeaderSize() {
        // This needs to be calculated properly. After a write, it's known. After a read, it needs to be tracked.
        if (headerSize > 0) return headerSize;
        // A rough estimation if not calculated.
        try (java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(options);
            return 8 // version
                 + bos.size() // options object
                 + 4 + salt.length // salt
                 + 4 + iv.length; // iv
        } catch (IOException e) {
            return 0; // fallback
        }
    }
}
