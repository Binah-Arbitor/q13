package com.example.myapplication.crypto;

public interface CryptoListener {
    void onProgress(float progress);
    void onSuccess(String result);
    void onError(String errorMessage);
    void onLog(String logMessage);
}
