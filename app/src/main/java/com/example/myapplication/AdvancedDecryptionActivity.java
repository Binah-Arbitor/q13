package com.example.myapplication;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;
import android.view.Menu;
import android.view.MenuItem;
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
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import com.example.myapplication.crypto.CryptoListener;
import com.example.myapplication.crypto.CryptoManager;
import com.example.myapplication.crypto.FileHeader;
import com.google.android.material.bottomnavigation.BottomNavigationView;

import java.io.InputStream;
import java.io.OutputStream;

public class AdvancedDecryptionActivity extends AppCompatActivity implements CryptoListener {

    // Permissions
    private static final String[] STORAGE_PERMISSIONS;
    static {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            STORAGE_PERMISSIONS = new String[]{Manifest.permission.READ_EXTERNAL_STORAGE};
        } else {
            STORAGE_PERMISSIONS = new String[]{Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE};
        }
    }

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
    private ActivityResultLauncher<String[]> requestPermissionsLauncher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_advanced_decryption);
        getSupportActionBar().setTitle("Advanced Decryption");

        cryptoManager = new CryptoManager(this, getApplicationContext());

        initializeViews();
        setupLaunchers();
        setupBottomNav();

        fileSelectButton.setOnClickListener(v -> checkPermissionsAndLaunchPicker());
        decryptButton.setOnClickListener(v -> handleDecryption());

        if (!hasStoragePermissions()) {
            requestStoragePermissions();
        }
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

        requestPermissionsLauncher = registerForActivityResult(
            new ActivityResultContracts.RequestMultiplePermissions(),
            permissions -> {
                if (permissions.values().stream().allMatch(g -> g)) {
                    onLog("Storage permissions granted.");
                } else {
                    Toast.makeText(this, "Storage permissions are required to select a file.", Toast.LENGTH_LONG).show();
                }
            }
        );
    }

    private void onFileSelected(Uri uri) {
        selectedFileUri = uri;
        String fileName = getFileName(uri);
        selectedFileTextView.setText("Selected file: " + fileName);
        onLog("File selected: " + fileName);
        headerInfoLayout.setVisibility(View.GONE); // Hide old info

        // Try to read the header
        try (InputStream inputStream = getContentResolver().openInputStream(selectedFileUri)) {
            if (inputStream == null) throw new Exception("Could not open input stream");
            cryptoManager.readHeader(inputStream, new CryptoManager.HeaderCallback() {
                @Override
                public void onHeaderRead(FileHeader header) {
                    runOnUiThread(() -> displayHeaderInfo(header));
                }

                @Override
                public void onError(Exception e) {
                    runOnUiThread(() -> AdvancedDecryptionActivity.this.onError("Failed to read file header: " + e.getMessage()));
                }
            });
        } catch (Exception e) {
            onError("Failed to open file: " + e.getMessage());
        }
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
            long totalSize;
            try (ParcelFileDescriptor pfd = getContentResolver().openFileDescriptor(selectedFileUri, "r")) {
                totalSize = pfd.getStatSize();
            }
            InputStream inputStream = getContentResolver().openInputStream(selectedFileUri);
            // Open the selected file for writing, which will overwrite it.
            OutputStream outputStream = getContentResolver().openOutputStream(selectedFileUri, "wt");

            if (inputStream == null || outputStream == null) {
                throw new Exception("Failed to open streams for the selected file.");
            }

            setUiEnabled(false);
            onLog("Starting advanced decryption...");

            cryptoManager.decryptAdvanced(password, inputStream, totalSize, outputStream);

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
            } else {
                lastProgress = -1;
                progressBar.setVisibility(View.VISIBLE);
                progressBar.setProgress(0);
                statusTextView.setVisibility(View.GONE);
            }
        });
    }

    private void checkPermissionsAndLaunchPicker() {
        if (!hasStoragePermissions()) requestPermissionsLauncher.launch(STORAGE_PERMISSIONS);
        else launchFilePicker();
    }

    private boolean hasStoragePermissions() {
        return ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED;
    }

    private void launchFilePicker() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("*/*");
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        filePickerLauncher.launch(Intent.createChooser(intent, "Select an encrypted file"));
    }

    private String getFileName(Uri uri) {
        String result = null;
        if ("content".equals(uri.getScheme())) {
            try (android.database.Cursor cursor = getContentResolver().query(uri, null, null, null, null)) {
                if (cursor != null && cursor.moveToFirst()) {
                    int nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    if (nameIndex != -1) result = cursor.getString(nameIndex);
                }
            }
        }
        if (result == null) {
            result = uri.getPath();
            if (result != null) {
                int cut = result.lastIndexOf('/');
                if (cut != -1) result = result.substring(cut + 1);
            }
        }
        return result != null ? result : "Unknown";
    }
    
    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main_menu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == R.id.action_settings) {
            startActivity(new Intent(this, SettingsActivity.class));
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void setupBottomNav() {
        bottomNav.setSelectedItemId(R.id.nav_advanced_decrypt);
        bottomNav.setOnNavigationItemSelectedListener(item -> {
            int itemId = item.getItemId();
            if (itemId == R.id.nav_advanced_decrypt) {
                return true; // Already here
            } else if (itemId == R.id.nav_advanced_encrypt) {
                Intent intent = new Intent(this, AdvancedEncryptionActivity.class);
                intent.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
                startActivity(intent);
                return true;
            }
            return false;
        });
    }

    // CryptoListener Implementation
    @Override public void onProgress(int progress) { runOnUiThread(() -> progressBar.setProgress(progress)); lastProgress = progress; }
    @Override public int getLastReportedProgress() { return lastProgress; }
    @Override public void onSuccess(String message) { runOnUiThread(() -> { setUiEnabled(true); statusTextView.setVisibility(View.VISIBLE); statusTextView.setText("✓ SUCCESS"); statusTextView.setTextColor(ContextCompat.getColor(this, R.color.success_green)); consoleTextView.append("\n[SUCCESS] " + message + "\n"); scrollToBottom(); Toast.makeText(this, "Operation Successful", Toast.LENGTH_SHORT).show(); }); }
    @Override public void onError(String errorMessage) { runOnUiThread(() -> { setUiEnabled(true); statusTextView.setVisibility(View.VISIBLE); statusTextView.setText("✗ ERROR"); statusTextView.setTextColor(ContextCompat.getColor(this, R.color.failure_red)); consoleTextView.append("\n[ERROR] " + errorMessage + "\n"); scrollToBottom(); Toast.makeText(this, "Error occurred", Toast.LENGTH_SHORT).show(); }); }
    @Override public void onLog(String logMessage) { runOnUiThread(() -> { consoleTextView.append(logMessage + "\n"); scrollToBottom(); }); }
    private void scrollToBottom() { consoleScrollView.post(() -> consoleScrollView.fullScroll(ScrollView.FOCUS_DOWN)); }
}
