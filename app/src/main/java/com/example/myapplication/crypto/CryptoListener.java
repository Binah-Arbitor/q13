package com.example.myapplication.crypto;

public interface CryptoListener {
    void onProgress(int progress);
    void onSuccess(String result);
    void onError(String errorMessage);
    void onLog(String logMessage);
    int getLastReportedProgress();
}
