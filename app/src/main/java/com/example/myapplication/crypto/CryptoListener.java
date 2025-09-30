package com.example.myapplication.crypto;

/**
 * A listener interface for receiving callbacks during an encryption or decryption process.
 * This allows the underlying crypto logic to report status back to the UI thread (or any other caller)
 * without being directly coupled to it.
 */
public interface CryptoListener {

    /**
     * Called periodically to report the progress of the operation.
     *
     * @param completedChunks The number of chunks that have been processed so far.
     * @param totalChunks     The total number of chunks for the entire operation.
     */
    void onProgress(long completedChunks, long totalChunks);

    /**
     * Called when the entire operation has completed successfully.
     *
     * @param message A success message.
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
        public void onProgress(long completedChunks, long totalChunks) {
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
