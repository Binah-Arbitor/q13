package com.example.myapplication;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.ActionBar;
import androidx.core.content.ContextCompat;
import com.example.myapplication.crypto.CryptoListener;
import com.example.myapplication.crypto.CryptoManager;
import com.example.myapplication.crypto.FileHeader;
import com.google.android.material.bottomnavigation.BottomNavigationView;

public class AdvancedDecryptionActivity extends BaseActivity implements CryptoListener {

    // UI Elements
    private Button fileSelectButton, decryptButton;
    private TextView selectedFileTextView, statusTextView;
    private EditText passwordInput;
    private LinearLayout headerInfoLayout;
    private TextView infoProtocol, infoKeyLength, infoMode, infoPadding, infoKdf;
    private ProgressBar progressBar;
    private ScrollView consoleScrollView;
    private TextView consoleTextView;
    private BottomNavigationView bottomNav;

    // State
    private Uri selectedFileUri;
    private CryptoManager cryptoManager;
    private FileHeader detectedHeader;
    private int lastProgress = -1;

    private ActivityResultLauncher<Intent> filePickerLauncher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_advanced_decryption);
        
        initializeViews();
        
        ActionBar actionBar = getSupportActionBar();
        if (actionBar != null) {
            actionBar.setTitle("Advanced Decryption");
        }

        cryptoManager = new CryptoManager(this, getApplicationContext());

        setupLaunchers();
        setupBottomNav();

        fileSelectButton.setOnClickListener(v -> checkPermissionsAndExecute(this::launchFilePicker));
        decryptButton.setOnClickListener(v -> handleDecryption());
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (bottomNav != null) {
            bottomNav.setSelectedItemId(R.id.nav_advanced_decrypt);
        }
    }

    @Override
    protected boolean isActivityForAdvancedMode() {
        return true;
    }

    private void initializeViews() {
        fileSelectButton = findViewById(R.id.file_select_button);
        decryptButton = findViewById(R.id.decrypt_button);
        selectedFileTextView = findViewById(R.id.selected_file_textview);
        passwordInput = findViewById(R.id.password_input);
        headerInfoLayout = findViewById(R.id.header_info_layout);
        infoProtocol = findViewById(R.id.info_protocol);
        infoKeyLength = findViewById(R.id.info_key_length);
        infoMode = findViewById(R.id.info_mode);
        infoPadding = findViewById(R.id.info_padding);
        infoKdf = findViewById(R.id.info_kdf);
        progressBar = findViewById(R.id.progress_bar);
        statusTextView = findViewById(R.id.status_textview);
        consoleScrollView = findViewById(R.id.console_scrollview);
        consoleTextView = findViewById(R.id.console_textview);
        bottomNav = findViewById(R.id.bottom_nav);
    }

    private void setupLaunchers() {
        filePickerLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            result -> {
                if (result.getResultCode() == Activity.RESULT_OK && result.getData() != null) {
                    onFileSelected(result.getData().getData());
                }
            }
        );
    }

    private void onFileSelected(Uri uri) {
        if (uri == null) return;
        selectedFileUri = uri;

        try {
            final int takeFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION;
            getContentResolver().takePersistableUriPermission(selectedFileUri, takeFlags);
        } catch (SecurityException e) {
            onLog("Could not get persistent permissions. May fail on reboot.");
        }

        String fileName = getFileName(uri);
        selectedFileTextView.setText("Selected file: " + fileName);
        onLog("File selected: " + fileName);
        headerInfoLayout.setVisibility(View.GONE); // Hide old info

        // CryptoManager now reads the header directly from the URI
        cryptoManager.readHeader(selectedFileUri, new CryptoManager.HeaderCallback() {
            @Override
            public void onHeaderRead(FileHeader header) {
                runOnUiThread(() -> displayHeaderInfo(header));
            }

            @Override
            public void onError(Exception e) {
                runOnUiThread(() -> AdvancedDecryptionActivity.this.onError("Failed to read file header: " + e.getMessage()));
            }
        });
    }

    private void displayHeaderInfo(FileHeader header) {
        this.detectedHeader = header;
        onLog("File header parsed successfully.");
        infoProtocol.setText("Protocol: " + header.getOptions().getProtocol());
        infoKeyLength.setText("Key Length: " + header.getOptions().getKeyLength() + "-bit");
        infoMode.setText("Mode: " + header.getOptions().getMode());
        infoPadding.setText("Padding: " + header.getOptions().getPadding());
        infoKdf.setText("KDF: " + header.getOptions().getKdf());
        headerInfoLayout.setVisibility(View.VISIBLE);
    }

    private void handleDecryption() {
        if (selectedFileUri == null) {
            onError("Please select a file first.");
            return;
        }
        if (detectedHeader == null) {
            onError("File header could not be read or is invalid. Cannot decrypt.");
            return;
        }
        String password = passwordInput.getText().toString();
        if (password.isEmpty()) {
            onError("Please enter a password.");
            return;
        }

        try {
            setUiEnabled(false);
            onLog("Starting advanced decryption...");

            // CryptoManager now handles all file IO via URI
            cryptoManager.decryptAdvanced(password, selectedFileUri);

        } catch (Exception e) {
            onError("Failed to start decryption: " + e.getMessage());
            setUiEnabled(true);
        }
    }

    private void setUiEnabled(boolean enabled) {
        runOnUiThread(() -> {
            decryptButton.setEnabled(enabled);
            fileSelectButton.setEnabled(enabled);
            passwordInput.setEnabled(enabled);

            if (enabled) {
                progressBar.setVisibility(View.GONE);
                 if(statusTextView != null) statusTextView.setVisibility(View.GONE);
            } else {
                lastProgress = -1;
                progressBar.setVisibility(View.VISIBLE);
                progressBar.setProgress(0);
                if(statusTextView != null) statusTextView.setVisibility(View.GONE);
            }
        });
    }

    private void launchFilePicker() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        filePickerLauncher.launch(intent);
    }

    private String getFileName(Uri uri) {
        String result = null;
        if (uri != null && "content".equals(uri.getScheme())) {
            try (android.database.Cursor cursor = getContentResolver().query(uri, null, null, null, null)) {
                if (cursor != null && cursor.moveToFirst()) {
                    int nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    if (nameIndex != -1) result = cursor.getString(nameIndex);
                }
            }
        }
        if (result == null && uri != null) {
            result = uri.getPath();
            if (result != null) {
                int cut = result.lastIndexOf('/');
                if (cut != -1) result = result.substring(cut + 1);
            }
        }
        return result != null ? result : "Unknown";
    }

    private void setupBottomNav() {
        bottomNav.setSelectedItemId(R.id.nav_advanced_decrypt);
        bottomNav.setOnItemSelectedListener(item -> {
            int itemId = item.getItemId();
            if (itemId == R.id.nav_advanced_decrypt) {
                // Already here
            } else if (itemId == R.id.nav_advanced_encrypt) {
                Intent intent = new Intent(this, AdvancedEncryptionActivity.class);
                intent.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT | Intent.FLAG_ACTIVITY_NO_ANIMATION);
                startActivity(intent);
                overridePendingTransition(0, 0);
            }
            return true;
        });
    }

    @Override public void onProgress(int progress) { runOnUiThread(() -> { if (progressBar != null) progressBar.setProgress(progress); }); lastProgress = progress; }
    @Override public int getLastReportedProgress() { return lastProgress; }
    @Override public void onSuccess(String message) { runOnUiThread(() -> { setUiEnabled(true); if(statusTextView != null) { statusTextView.setVisibility(View.VISIBLE); statusTextView.setText("✓ SUCCESS"); statusTextView.setTextColor(ContextCompat.getColor(this, R.color.success_green)); } if (consoleTextView != null) consoleTextView.append("\n[SUCCESS] " + message + "\n"); scrollToBottom(); Toast.makeText(this, "Operation Successful", Toast.LENGTH_SHORT).show(); }); }
    @Override public void onError(String errorMessage) { runOnUiThread(() -> { setUiEnabled(true); if(statusTextView != null) { statusTextView.setVisibility(View.VISIBLE); statusTextView.setText("✗ ERROR"); statusTextView.setTextColor(ContextCompat.getColor(this, R.color.failure_red)); } if(consoleTextView != null) consoleTextView.append("\n[ERROR] " + errorMessage + "\n"); scrollToBottom(); Toast.makeText(this, "Error occurred", Toast.LENGTH_SHORT).show(); }); }
    @Override public void onLog(String logMessage) { runOnUiThread(() -> { if(consoleTextView != null) consoleTextView.append(logMessage + "\n"); scrollToBottom(); }); }
    private void scrollToBottom() { if(consoleScrollView != null) { consoleScrollView.post(() -> consoleScrollView.fullScroll(ScrollView.FOCUS_DOWN)); } }
}
