package com.example.myapplication;

import android.content.ContentResolver;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.SeekBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import com.example.myapplication.crypto.CryptoListener;
import com.example.myapplication.crypto.CryptoManager;
import com.example.myapplication.crypto.CryptoOptions;
import com.example.myapplication.crypto.FileHeader;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AdvancedDecryptionActivity extends AppCompatActivity implements CryptoListener {

    private Button fileSelectButton, decryptButton;
    private TextView selectedFileTextView, consoleTextView, threadCountValueTextView;
    private EditText passwordInput;
    private LinearLayout headerInfoLayout;
    private TextView infoProtocol, infoKeyLength, infoBlockSize, infoMode, infoPadding, infoKdf;
    private ProgressBar progressBar;
    private ScrollView consoleScrollView;
    private SeekBar threadCountSlider;

    private Uri selectedFileUri;
    private String currentFilePath;
    private final CryptoManager cryptoManager = new CryptoManager();
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private ActivityResultLauncher<Intent> filePickerLauncher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_advanced_decryption);
        setTitle("Advanced Decryption");

        initializeViews();
        setupFilePicker();
        setupEventListeners();
    }

    private void initializeViews() {
        fileSelectButton = findViewById(R.id.file_select_button);
        decryptButton = findViewById(R.id.decrypt_button);
        selectedFileTextView = findViewById(R.id.selected_file_textview);
        passwordInput = findViewById(R.id.password_input);
        headerInfoLayout = findViewById(R.id.header_info_layout);
        infoProtocol = findViewById(R.id.info_protocol);
        infoKeyLength = findViewById(R.id.info_key_length);
        infoBlockSize = findViewById(R.id.info_block_size);
        infoMode = findViewById(R.id.info_mode);
        infoPadding = findViewById(R.id.info_padding);
        infoKdf = findViewById(R.id.info_kdf);
        progressBar = findViewById(R.id.progress_bar);
        consoleScrollView = findViewById(R.id.console_scrollview);
        consoleTextView = findViewById(R.id.console_textview);
        threadCountSlider = findViewById(R.id.thread_count_slider);
        threadCountValueTextView = findViewById(R.id.thread_count_value_textview);
    }

    private void setupFilePicker() {
        filePickerLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == RESULT_OK && result.getData() != null) {
                        onFileSelected(result.getData().getData());
                    }
                });
    }

    private void setupEventListeners() {
        fileSelectButton.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            intent.setType("*/*");
            filePickerLauncher.launch(intent);
        });

        decryptButton.setOnClickListener(v -> handleDecryption());

        int maxThreads = Math.max(1, Runtime.getRuntime().availableProcessors() * 2 - 2);
        threadCountSlider.setMax(maxThreads - 1);
        threadCountSlider.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
            @Override
            public void onProgressChanged(SeekBar seekBar, int progress, boolean fromUser) {
                threadCountValueTextView.setText(String.valueOf(progress + 1));
            }
            @Override public void onStartTrackingTouch(SeekBar seekBar) {} 
            @Override public void onStopTrackingTouch(SeekBar seekBar) {}
        });
        threadCountValueTextView.setText("1"); // Default to 1 thread
    }

    private void onFileSelected(Uri uri) {
        selectedFileUri = uri;
        selectedFileTextView.setText(getFileName(uri));
        headerInfoLayout.setVisibility(View.GONE);
        onLog("File selected. Reading header...");

        setUiEnabled(false);
        executor.submit(() -> {
            currentFilePath = getPathFromUri(uri);
            if (currentFilePath != null) {
                try {
                    CryptoOptions options = FileHeader.peekOptions(currentFilePath);
                    runOnUiThread(() -> {
                        displayHeaderInfo(options);
                        setUiEnabled(true);
                    });
                } catch (Exception e) {
                    onError("Failed to read or parse file header.", e);
                }
            } else {
                 runOnUiThread(() -> setUiEnabled(true)); // Re-enable UI if path resolving fails
            }
        });
    }

    private void displayHeaderInfo(CryptoOptions options) {
        onLog("Header read successfully. Details below:");
        infoProtocol.setText("Protocol: " + options.getProtocol().getName());
        infoKeyLength.setText("Key Length: " + options.getKeyLength() + "-bit");
        infoBlockSize.setText("Block Size: " + options.getBlockBitSize() + "-bit");
        infoMode.setText("Mode: " + options.getMode().name());
        infoPadding.setText("Padding: " + options.getPadding().name());
        infoKdf.setText("KDF: " + options.getKdf());
        headerInfoLayout.setVisibility(View.VISIBLE);
    }

    private void handleDecryption() {
        if (currentFilePath == null) {
            onError("No valid file selected or file path could not be resolved.", null);
            return;
        }
        char[] password = passwordInput.getText().toString().toCharArray();
        if (password.length == 0) {
            onError("Password cannot be empty.", null);
            return;
        }

        try {
            int threads = threadCountSlider.getProgress() + 1;
            int chunkSize = 1024 * 1024; // 1 MB, can be adjusted

            String destPath = currentFilePath.endsWith(".enc") ? currentFilePath.substring(0, currentFilePath.length() - 4) : currentFilePath + ".dec";

            setUiEnabled(false);
            onLog("Starting decryption with " + threads + " thread(s)...");

            executor.submit(() -> {
                try {
                    cryptoManager.decrypt(currentFilePath, destPath, password, chunkSize, threads, this);
                } catch (Exception e) {
                    onError("Decryption failed", e);
                }
            });

        } catch (Exception e) {
            onError("Failed to start decryption", e);
        }
    }

    private void setUiEnabled(boolean enabled) {
        runOnUiThread(() -> {
            decryptButton.setEnabled(enabled);
            fileSelectButton.setEnabled(enabled);
            passwordInput.setEnabled(enabled);
            threadCountSlider.setEnabled(enabled);
            progressBar.setVisibility(enabled ? View.INVISIBLE : View.VISIBLE);
        });
    }

    private String getPathFromUri(Uri uri) {
        File tempFile = null;
        try {
            String fileName = getFileName(uri);
            tempFile = File.createTempFile("decrypt_temp", fileName, getCacheDir());
            tempFile.deleteOnExit();
            try (InputStream in = getContentResolver().openInputStream(uri); FileOutputStream out = new FileOutputStream(tempFile)) {
                byte[] buffer = new byte[8192];
                int len;
                while ((len = in.read(buffer)) != -1) {
                    out.write(buffer, 0, len);
                }
            }
            return tempFile.getAbsolutePath();
        } catch (Exception e) {
            if (tempFile != null) tempFile.delete();
            onError("Failed to process file URI. Please use a file stored locally.", e);
            return null;
        }
    }

    private String getFileName(Uri uri) {
        String result = "tempfile";
        if ("content".equals(uri.getScheme())) {
            try (Cursor cursor = getContentResolver().query(uri, null, null, null, null)) {
                if (cursor != null && cursor.moveToFirst()) {
                    int nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    if (nameIndex != -1) result = cursor.getString(nameIndex);
                }
            }
        }
        return result;
    }

    // CryptoListener Implementation
    @Override
    public void onStart(long totalBytes) {
        runOnUiThread(() -> {
            progressBar.setProgress(0);
            progressBar.setMax(100);
            onLog("Processing " + totalBytes + " bytes...");
        });
    }

    @Override
    public void onProgress(long current, long total) {
        int progress = (int) ((current * 100) / total);
        runOnUiThread(() -> progressBar.setProgress(progress));
    }

    @Override
    public void onSuccess(String message) {
        runOnUiThread(() -> {
            setUiEnabled(true);
            onLog("[SUCCESS] " + message);
            Toast.makeText(this, "Decryption Successful!", Toast.LENGTH_SHORT).show();
        });
    }

    @Override
    public void onError(String message, Exception e) {
        runOnUiThread(() -> {
            setUiEnabled(true);
            String exceptionMessage = e != null ? e.getClass().getSimpleName() + ": " + e.getMessage() : "";
            String logMsg = "[ERROR] " + message + "\n" + exceptionMessage;
            onLog(logMsg);
            Toast.makeText(this, "An Error Occurred", Toast.LENGTH_SHORT).show();
        });
    }

    private void onLog(String message) {
        runOnUiThread(() -> {
            consoleTextView.append(message + "\n");
            consoleScrollView.post(() -> consoleScrollView.fullScroll(View.FOCUS_DOWN));
        });
    }
}
