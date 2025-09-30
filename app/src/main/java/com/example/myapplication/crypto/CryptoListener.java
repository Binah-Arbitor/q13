package com.example.myapplication.crypto;

/**
 * A listener interface for receiving callbacks during an encryption or decryption process.
 */
public interface CryptoListener {

    /**
     * Called once at the beginning of the operation, providing the total size of the data to be processed.
     *
     * @param totalBytes The total number of bytes to be processed.
     */
    void onStart(long totalBytes);

    /**
     * Called periodically to report the progress of the operation.
     *
     * @param currentBytes The number of bytes that have been processed so far.
     * @param totalBytes   The total number of bytes for the entire operation.
     */
    void onProgress(long currentBytes, long totalBytes);

    /**
     * Called when the entire operation has completed successfully.
     *
     * @param message A success message, which could include the path to the output file.
     */
    void onSuccess(String message);

    /**
     * Called if an error occurs at any point during the operation.
     *
     * @param message An error message describing what went wrong.
     * @param e       The exception that occurred. This can be null.
     */
    void onError(String message, Exception e);

    /**
     * A default "do nothing" implementation of the listener for convenience.
     */
    CryptoListener DEFAULT = new CryptoListener() {
        @Override
        public void onStart(long totalBytes) {
            // Do nothing
        }

        @Override
        public void onProgress(long currentBytes, long totalBytes) {
            // Do nothing
        }

        @Override
        public void onSuccess(String message) {
            // Do nothing
        }

        @Override
        public void onError(String message, Exception e) {
            // Do nothing
        }
    };
}
