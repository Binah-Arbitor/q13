package com.example.myapplication;

import android.content.ContentResolver;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import com.example.myapplication.crypto.CryptoListener;
import com.example.myapplication.crypto.CryptoManager;
import com.example.myapplication.crypto.CryptoOptions;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SimpleEncryptionActivity extends AppCompatActivity implements CryptoListener {

    private EditText passwordInput;
    private Button fileSelectButton, encryptButton;
    private TextView selectedFileTextView, consoleTextView;
    private ProgressBar progressBar;
    private ScrollView consoleScrollView;
    private Spinner modeSpinner;

    private Uri selectedFileUri;
    private String selectedMode;
    private final CryptoManager cryptoManager = new CryptoManager();
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private ActivityResultLauncher<Intent> filePickerLauncher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_simple_encryption);
        setTitle("Simple Encryption");

        initializeViews();
        setupFilePicker();
        setupSpinner();
        setupEventListeners();
    }

    private void initializeViews() {
        passwordInput = findViewById(R.id.password_input);
        fileSelectButton = findViewById(R.id.file_select_button);
        encryptButton = findViewById(R.id.encrypt_button);
        selectedFileTextView = findViewById(R.id.selected_file_textview);
        progressBar = findViewById(R.id.progress_bar);
        consoleTextView = findViewById(R.id.console_textview);
        consoleScrollView = findViewById(R.id.console_scrollview);
        modeSpinner = findViewById(R.id.mode_spinner); // Assuming this ID exists in the layout
    }

    private void setupFilePicker() {
        filePickerLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == RESULT_OK && result.getData() != null) {
                        selectedFileUri = result.getData().getData();
                        selectedFileTextView.setText(getFileName(selectedFileUri));
                    }
                });
    }

    private void setupSpinner() {
        String[] modes = {"Efficiency", "Performance"};
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, modes);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        modeSpinner.setAdapter(adapter);
        modeSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                selectedMode = (String) parent.getItemAtPosition(position);
            }
            @Override
            public void onNothingSelected(AdapterView<?> parent) {
                selectedMode = modes[0];
            }
        });
        selectedMode = modes[0]; // Default selection
    }

    private void setupEventListeners() {
        fileSelectButton.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            intent.setType("*/*");
            filePickerLauncher.launch(intent);
        });

        encryptButton.setOnClickListener(v -> handleEncryption());
    }

    private void handleEncryption() {
        if (selectedFileUri == null) {
            onError("Please select a file.", null);
            return;
        }
        char[] password = passwordInput.getText().toString().toCharArray();
        if (password.length == 0) {
            onError("Password cannot be empty.", null);
            return;
        }

        try {
            CryptoOptions options = CryptoOptions.getDefault(); // Hardcoded to AES-256-GCM

            int threads;
            if ("Performance".equals(selectedMode)) {
                threads = Math.max(1, Runtime.getRuntime().availableProcessors() * 2 - 2);
            } else { // "Efficiency"
                threads = 1;
            }

            int chunkSize = 1024 * 1024; // 1 MB chunk size

            String sourcePath = getPathFromUri(selectedFileUri);
            if (sourcePath == null) {
                onError("Could not get file path. Please select a locally stored file.", null);
                return;
            }
            String destPath = sourcePath + ".enc";

            setUiEnabled(false);
            onLog("Starting encryption (AES-256-GCM, " + selectedMode + " Mode, " + threads + " threads)...");

            executor.submit(() -> {
                try {
                    cryptoManager.encrypt(sourcePath, destPath, password, options, chunkSize, threads, this);
                } catch (Exception e) {
                    onError("Encryption failed", e);
                }
            });

        } catch (Exception e) {
            onError("Failed to start encryption", e);
        }
    }

    private void setUiEnabled(boolean enabled) {
        runOnUiThread(() -> {
            passwordInput.setEnabled(enabled);
            fileSelectButton.setEnabled(enabled);
            encryptButton.setEnabled(enabled);
            modeSpinner.setEnabled(enabled);
            progressBar.setVisibility(enabled ? View.INVISIBLE : View.VISIBLE);
        });
    }

    private String getPathFromUri(Uri uri) {
        File tempFile = null;
        try {
            String fileName = getFileName(uri);
            tempFile = File.createTempFile("temp_prefix", fileName, getCacheDir());
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
            onError("Failed to process file URI", e);
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
            Toast.makeText(this, "Encryption Successful!", Toast.LENGTH_SHORT).show();
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
