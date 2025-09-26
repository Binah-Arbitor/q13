package com.example.myapplication;

import android.app.Activity;
import android.content.Intent;
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
import androidx.core.content.ContextCompat;
import com.example.myapplication.crypto.CryptoListener;
import com.example.myapplication.crypto.CryptoManager;
import com.google.android.material.bottomnavigation.BottomNavigationView;

public class SimpleEncryptionActivity extends BaseActivity implements CryptoListener {

    private Spinner modeSpinner;
    private EditText passwordInput;
    private Button fileSelectButton, encryptButton;
    private TextView selectedFileTextView, statusTextView;
    private ProgressBar progressBar;
    private ScrollView consoleScrollView;
    private TextView consoleTextView;
    private BottomNavigationView bottomNav;

    private Uri selectedFileUri;
    private CryptoManager cryptoManager;
    private String selectedMode = "Efficiency (Single-Thread)";
    private int lastProgress = -1;

    private ActivityResultLauncher<Intent> filePickerLauncher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_simple_encryption);
        getSupportActionBar().setTitle("Simple Encryption");

        cryptoManager = new CryptoManager(this, getApplicationContext());

        initializeViews();
        setupLaunchers();
        setupSpinner();
        setupBottomNav();

        fileSelectButton.setOnClickListener(v -> checkPermissionsAndExecute(this::launchFilePicker));
        encryptButton.setOnClickListener(v -> handleEncryption());
    }

    @Override
    protected boolean isActivityForAdvancedMode() {
        return false;
    }

    private void initializeViews() {
        modeSpinner = findViewById(R.id.mode_spinner);
        passwordInput = findViewById(R.id.password_input);
        fileSelectButton = findViewById(R.id.file_select_button);
        selectedFileTextView = findViewById(R.id.selected_file_textview);
        encryptButton = findViewById(R.id.encrypt_button);
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
                    selectedFileUri = result.getData().getData();
                    if (selectedFileUri != null) {
                        // Persist read/write permissions
                        final int takeFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION;
                        try {
                            getContentResolver().takePersistableUriPermission(selectedFileUri, takeFlags);
                        } catch (SecurityException e) {
                            e.printStackTrace();
                            onLog("Could not get persistent permissions. May fail on reboot.");
                        }
                        String fileName = getFileName(selectedFileUri);
                        selectedFileTextView.setText("Selected file: " + fileName);
                        onLog("File selected: " + fileName);
                    }
                }
            }
        );
    }

    private void launchFilePicker() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        filePickerLauncher.launch(intent);
    }

    private void handleEncryption() {
        if (selectedFileUri == null) {
            onError("Please select a file first.");
            return;
        }
        String password = passwordInput.getText().toString();
        if (password.isEmpty()) {
            onError("Please enter a password.");
            return;
        }

        setUiEnabled(false);
        final boolean useMultithreading = "Performance (Pipeline)".equals(selectedMode);
        String modeLog = useMultithreading ? "Performance (Parallel)" : "Efficiency (Single-Thread)";
        onLog("Starting encryption in " + modeLog + " mode...");

        try {
            // The CryptoManager now handles all file operations directly via URI
            cryptoManager.encrypt(password, selectedFileUri, useMultithreading);
        } catch (Exception e) {
            onError("Failed to start encryption: " + e.getMessage());
            setUiEnabled(true); // Re-enable UI on failure
        }
    }

    private void setUiEnabled(boolean enabled) {
        runOnUiThread(() -> {
            encryptButton.setEnabled(enabled);
            fileSelectButton.setEnabled(enabled);
            modeSpinner.setEnabled(enabled);
            passwordInput.setEnabled(enabled);

            if (enabled) {
                progressBar.setVisibility(View.GONE);
                statusTextView.setVisibility(View.GONE);
            } else {
                lastProgress = -1; // Reset progress
                progressBar.setVisibility(View.VISIBLE);
                progressBar.setProgress(0);
                statusTextView.setVisibility(View.GONE);
            }
        });
    }

    private void setupSpinner() {
        String[] modes = {"Efficiency (Single-Thread)", "Performance (Pipeline)"};
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, modes);
        modeSpinner.setAdapter(adapter);
        modeSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                selectedMode = (String) parent.getItemAtPosition(position);
            }
            @Override
            public void onNothingSelected(AdapterView<?> parent) { }
        });
    }

    private void setupBottomNav() {
        bottomNav.setSelectedItemId(R.id.nav_simple_encrypt);
        bottomNav.setOnItemSelectedListener(item -> {
            int itemId = item.getItemId();
            if (itemId == R.id.nav_simple_encrypt) {
                // Do nothing
            } else if (itemId == R.id.nav_simple_decrypt) {
                Intent intent = new Intent(this, SimpleDecryptionActivity.class);
                intent.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT | Intent.FLAG_ACTIVITY_NO_ANIMATION);
                startActivity(intent);
                overridePendingTransition(0, 0);
            }
            return true;
        });
    }

    private String getFileName(Uri uri) {
        String result = null;
        if ("content".equals(uri.getScheme())) {
            try (android.database.Cursor cursor = getContentResolver().query(uri, null, null, null, null)) {
                if (cursor != null && cursor.moveToFirst()) {
                    int nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    if (nameIndex != -1) {
                         result = cursor.getString(nameIndex);
                    }
                }
            }
        }
        if (result == null) {
            result = uri.getPath();
            if (result == null) return "Unknown";
            int cut = result.lastIndexOf('/');
            if (cut != -1) {
                result = result.substring(cut + 1);
            }
        }
        return result;
    }

    // CryptoListener Implementation
    @Override
    public void onProgress(int progress) {
        runOnUiThread(() -> {
            progressBar.setProgress(progress);
            lastProgress = progress;
        });
    }
    
    @Override
    public int getLastReportedProgress() {
        return lastProgress;
    }

    @Override
    public void onSuccess(String result) {
        runOnUiThread(() -> {
            setUiEnabled(true);
            statusTextView.setVisibility(View.VISIBLE);
            statusTextView.setText("✓ SUCCESS");
            statusTextView.setTextColor(ContextCompat.getColor(this, R.color.success_green));
            consoleTextView.append("\n[SUCCESS] " + result + "\n");
            scrollToBottom();
            Toast.makeText(this, "Operation Successful", Toast.LENGTH_SHORT).show();
        });
    }

    @Override
    public void onError(String errorMessage) {
        runOnUiThread(() -> {
            setUiEnabled(true);
            statusTextView.setVisibility(View.VISIBLE);
            statusTextView.setText("✗ ERROR");
            statusTextView.setTextColor(ContextCompat.getColor(this, R.color.failure_red));
            consoleTextView.append("\n[ERROR] " + errorMessage + "\n");
            scrollToBottom();
            Toast.makeText(this, "Error occurred", Toast.LENGTH_SHORT).show();
        });
    }

    @Override
    public void onLog(String logMessage) {
        runOnUiThread(() -> {
            consoleTextView.append(logMessage + "\n");
            scrollToBottom();
        });
    }

    private void scrollToBottom() {
        consoleScrollView.post(() -> consoleScrollView.fullScroll(ScrollView.FOCUS_DOWN));
    }
}
