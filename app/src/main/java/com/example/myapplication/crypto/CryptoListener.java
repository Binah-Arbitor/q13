package com.example.myapplication.crypto;

public interface CryptoListener {

    void onStart(long totalBytes);

    void onProgress(long currentBytes, long totalBytes);

    void onSuccess(String message, String outputPath);

    void onError(String message, Exception e);

    void onLog(String message);

}
