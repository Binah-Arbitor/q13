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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SimpleEncryptionActivity extends AppCompatActivity implements CryptoListener {

    private EditText passwordInput;
    private Button fileSelectButton, encryptButton;
    private TextView selectedFileTextView, consoleTextView, statusTextView;
    private ProgressBar progressBar;
    private ScrollView consoleScrollView;
    private Spinner modeSpinner;

    private Uri selectedFileUri;
    private String sourcePathForTempFile; // To keep track of the temporary file
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
        statusTextView = findViewById(R.id.status_textview);
        modeSpinner = findViewById(R.id.mode_spinner);
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
            sourcePathForTempFile = getPathFromUri(selectedFileUri); 
            if (sourcePathForTempFile == null) return;

            CryptoOptions options = CryptoOptions.getDefault();
            int threads = "Performance".equals(selectedMode) ? Math.max(2, Runtime.getRuntime().availableProcessors()) : 1;
            int chunkSize = 1024 * 1024; // 1 MB
            String destPath = getCacheDir().getAbsolutePath() + "/" + getFileName(selectedFileUri) + ".enc";

            resetUiState();
            setUiEnabled(false);
            onLog("Starting encryption...");

            executor.submit(() -> {
                try {
                    cryptoManager.encrypt(sourcePathForTempFile, destPath, password, options, chunkSize, threads, this);
                } catch (Exception e) {
                    onError("Encryption failed", e);
                }
            });

        } catch (Exception e) {
            onError("Failed to start encryption", e);
        }
    }

    @Override
    public void onSuccess(String message, String outputPath) {
        runOnUiThread(() -> {
            onLog("[SUCCESS] " + message);
            onLog("Overwriting original file...");
            try {
                overwriteOriginalFile(outputPath);
                onLog("File overwritten successfully.");
                Toast.makeText(this, "Encryption Successful!", Toast.LENGTH_SHORT).show();
                statusTextView.setText("✓ SUCCESS");
            } catch (Exception e) {
                onError("Failed to overwrite original file", e);
            } finally {
                cleanupTempFiles(outputPath);
                setUiEnabled(true);
                statusTextView.setVisibility(View.VISIBLE);
            }
        });
    }
    
    private void overwriteOriginalFile(String resultPath) throws Exception {
        if (selectedFileUri == null) {
            throw new IllegalStateException("Original file URI is missing.");
        }
        ContentResolver resolver = getContentResolver();
        try (InputStream in = new FileInputStream(resultPath); 
             OutputStream out = resolver.openOutputStream(selectedFileUri, "wt")) { // 'wt' for write and truncate
            if (out == null) {
                throw new IOException("Failed to open output stream for URI: " + selectedFileUri.toString());
            }
            byte[] buffer = new byte[8192];
            int len;
            while ((len = in.read(buffer)) != -1) {
                out.write(buffer, 0, len);
            }
        }
    }
    
    private void cleanupTempFiles(String encryptedFilePath) {
        if (sourcePathForTempFile != null) {
            new File(sourcePathForTempFile).delete();
            sourcePathForTempFile = null;
        }
        if (encryptedFilePath != null) {
            new File(encryptedFilePath).delete();
        }
    }

    // Other methods (UI, file handling, listeners) remain largely the same...

    private void setUiEnabled(boolean enabled) {
        runOnUiThread(() -> {
            passwordInput.setEnabled(enabled);
            fileSelectButton.setEnabled(enabled);
            encryptButton.setEnabled(enabled);
            modeSpinner.setEnabled(enabled);
            progressBar.setVisibility(enabled ? View.GONE : View.VISIBLE);
            if(enabled) progressBar.setProgress(0);
        });
    }
    
    private void resetUiState() {
        runOnUiThread(() -> {
            consoleTextView.setText("");
            statusTextView.setVisibility(View.GONE);
        });
    }

    private String getPathFromUri(Uri uri) {
        try {
            // Use a unique name to avoid potential conflicts
            String tempFileName = "temp_simple_enc_" + System.currentTimeMillis();
            File tempFile = File.createTempFile(tempFileName, ".tmp", getCacheDir());
            // No need for deleteOnExit() as we will manage it manually
            try (InputStream in = getContentResolver().openInputStream(uri); 
                 FileOutputStream out = new FileOutputStream(tempFile)) {
                byte[] buffer = new byte[8192];
                int len;
                while ((len = in.read(buffer)) != -1) {
                    out.write(buffer, 0, len);
                }
            }
            return tempFile.getAbsolutePath();
        } catch (Exception e) {
            onError("Failed to create a temporary file from URI", e);
            return null;
        }
    }

    private String getFileName(Uri uri) {
        String result = "file.tmp";
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

    @Override
    public void onStart(long totalBytes) {
        runOnUiThread(() -> {
            progressBar.setMax((int) totalBytes);
            progressBar.setProgress(0);
            onLog("Processing " + totalBytes + " bytes...");
        });
    }

    @Override
    public void onProgress(long currentBytes, long totalBytes) {
        runOnUiThread(() -> progressBar.setProgress((int) currentBytes));
    }

    @Override
    public void onError(String message, Exception e) {
        runOnUiThread(() -> {
            setUiEnabled(true);
            statusTextView.setText("✗ ERROR");
            statusTextView.setVisibility(View.VISIBLE);
            String logMsg = "[ERROR] " + message + (e != null ? ": " + e.getMessage() : "");
            onLog(logMsg);
            if (e != null) {
                e.printStackTrace();
            }
            Toast.makeText(this, "An Error Occurred", Toast.LENGTH_SHORT).show();
        });
    }

    public void onLog(String message) {
        runOnUiThread(() -> {
            consoleTextView.append(message + "\n");
            consoleScrollView.post(() -> consoleScrollView.fullScroll(View.FOCUS_DOWN));
        });
    }
}
