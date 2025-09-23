package com.example.myapplication.crypto;

public interface CryptoListener {

    /**
     * Called to update the progress of the encryption/decryption process.
     * @param progress A value from 0 to 100.
     */
    void onProgress(int progress);

    /**
     * Called when the operation completes successfully.
     * @param result A message or result of the operation (e.g., path to the output file).
     */
    void onSuccess(String result);

    /**
     * Called when an error occurs during the operation.
     * @param errorMessage A description of the error.
     */
    void onError(String errorMessage);

    /**
     * Called to provide detailed log messages during the process.
     * @param logMessage A log message to be displayed in a console.
     */
    void onLog(String logMessage);

}
