package com.example.myapplication;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
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
import com.google.android.material.bottomnavigation.BottomNavigationView;

public class AdvancedEncryptionActivity extends AppCompatActivity implements CryptoListener {

    // Permissions
    private static final String[] STORAGE_PERMISSIONS;
    static {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            STORAGE_PERMISSIONS = new String[]{Manifest.permission.READ_EXTERNAL_STORAGE};
        } else {
            STORAGE_PERMISSIONS = new String[]{Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE};
        }
    }

    private Button publicKeySelectButton, privateKeySelectButton, fileSelectButton, encryptButton;
    private TextView publicKeyTextView, privateKeyTextView, selectedFileTextView, statusTextView;
    private EditText passphraseInput;
    private CheckBox signCheckBox;
    private ProgressBar progressBar;
    private ScrollView consoleScrollView;
    private TextView consoleTextView;
    private BottomNavigationView bottomNav;

    private Uri publicKeyUri, privateKeyUri, selectedFileUri;
    private CryptoManager cryptoManager;
    private int lastProgress = -1;

    private ActivityResultLauncher<Intent> publicKeyFilePickerLauncher;
    private ActivityResultLauncher<Intent> privateKeyFilePickerLauncher;
    private ActivityResultLauncher<Intent> fileToEncryptPickerLauncher;
    private ActivityResultLauncher<String[]> requestPermissionsLauncher;

    private ActivityResultLauncher<Intent> currentlyWaitingLauncher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_advanced_encryption);
        getSupportActionBar().setTitle("Advanced Encryption");

        cryptoManager = new CryptoManager(this, getApplicationContext());

        setupLaunchers();

        publicKeySelectButton = findViewById(R.id.public_key_select_button);
        privateKeySelectButton = findViewById(R.id.private_key_select_button);
        fileSelectButton = findViewById(R.id.file_select_button);
        encryptButton = findViewById(R.id.encrypt_button);
        publicKeyTextView = findViewById(R.id.public_key_textview);
        privateKeyTextView = findViewById(R.id.private_key_textview);
        selectedFileTextView = findViewById(R.id.selected_file_textview);
        passphraseInput = findViewById(R.id.passphrase_input);
        signCheckBox = findViewById(R.id.sign_checkbox);
        progressBar = findViewById(R.id.progress_bar);
        statusTextView = findViewById(R.id.status_textview);
        consoleScrollView = findViewById(R.id.console_scrollview);
        consoleTextView = findViewById(R.id.console_textview);
        bottomNav = findViewById(R.id.bottom_nav);

        setupBottomNav();

        publicKeySelectButton.setOnClickListener(v -> checkPermissionsAndLaunchPicker(publicKeyFilePickerLauncher, "Select Public Key"));
        privateKeySelectButton.setOnClickListener(v -> checkPermissionsAndLaunchPicker(privateKeyFilePickerLauncher, "Select Private Key"));
        fileSelectButton.setOnClickListener(v -> checkPermissionsAndLaunchPicker(fileToEncryptPickerLauncher, "Select File to Encrypt"));

        encryptButton.setOnClickListener(v -> handleEncryption());

        if (!hasStoragePermissions()) {
            requestStoragePermissions();
        }
    }

    private void setupLaunchers() {
        publicKeyFilePickerLauncher = createAndRegisterLauncher(publicKeyTextView, "Public Key: ", uri -> publicKeyUri = uri);
        privateKeyFilePickerLauncher = createAndRegisterLauncher(privateKeyTextView, "Private Key: ", uri -> privateKeyUri = uri);
        fileToEncryptPickerLauncher = createAndRegisterLauncher(selectedFileTextView, "File: ", uri -> selectedFileUri = uri);

        requestPermissionsLauncher = registerForActivityResult(
            new ActivityResultContracts.RequestMultiplePermissions(),
            permissions -> {
                boolean allGranted = true;
                for (Boolean granted : permissions.values()) {
                    if (!granted) {
                        allGranted = false;
                        break;
                    }
                }
                if (allGranted) {
                    onLog("Storage permissions granted.");
                    if (currentlyWaitingLauncher != null) {
                        launchFilePicker(currentlyWaitingLauncher, "Select File");
                        currentlyWaitingLauncher = null;
                    }
                } else {
                    Toast.makeText(this, "Storage permissions are required to select files.", Toast.LENGTH_LONG).show();
                }
            }
        );
    }

    private ActivityResultLauncher<Intent> createAndRegisterLauncher(TextView textView, String prefix, UriConsumer uriConsumer) {
        return registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            result -> {
                if (result.getResultCode() == Activity.RESULT_OK && result.getData() != null) {
                    Uri uri = result.getData().getData();
                    if (uri != null) {
                        uriConsumer.accept(uri);
                        String fileName = getFileName(uri);
                        textView.setText(prefix + fileName);
                    }
                }
            }
        );
    }

    private void checkPermissionsAndLaunchPicker(ActivityResultLauncher<Intent> launcher, String title) {
        if (hasStoragePermissions()) {
            launchFilePicker(launcher, title);
        } else {
            currentlyWaitingLauncher = launcher;
            requestStoragePermissions();
        }
    }

    private boolean hasStoragePermissions() {
        for (String permission : STORAGE_PERMISSIONS) {
            if (ContextCompat.checkSelfPermission(this, permission) != PackageManager.PERMISSION_GRANTED) {
                return false;
            }
        }
        return true;
    }

    private void requestStoragePermissions() {
        requestPermissionsLauncher.launch(STORAGE_PERMISSIONS);
    }

    private void launchFilePicker(ActivityResultLauncher<Intent> launcher, String title) {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("*/*");
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        launcher.launch(Intent.createChooser(intent, title));
    }

    @FunctionalInterface
    interface UriConsumer {
        void accept(Uri uri);
    }

    private void handleEncryption() {
        setUiEnabled(false);
        onError("PGP encryption is not yet implemented.");
    }

    private void setUiEnabled(boolean enabled) {
        runOnUiThread(() -> {
            encryptButton.setEnabled(enabled);
            fileSelectButton.setEnabled(enabled);
            publicKeySelectButton.setEnabled(enabled);
            privateKeySelectButton.setEnabled(enabled);
            passphraseInput.setEnabled(enabled);
            signCheckBox.setEnabled(enabled);

            if (enabled) {
                progressBar.setVisibility(View.GONE);
            } else {
                lastProgress = -1; // Reset progress
                progressBar.setVisibility(View.VISIBLE);
                progressBar.setProgress(0);
                statusTextView.setVisibility(View.GONE);
            }
        });
    }

    private void setupBottomNav() {
        bottomNav.setSelectedItemId(R.id.nav_advanced_encrypt);
        bottomNav.setOnNavigationItemSelectedListener(item -> {
             int itemId = item.getItemId();
            if (itemId == R.id.nav_simple_encrypt) {
                startActivity(new Intent(this, SimpleEncryptionActivity.class));
                return true;
            } else if (itemId == R.id.nav_advanced_encrypt) {
                return true;
            } else if (itemId == R.id.nav_simple_decrypt) {
                startActivity(new Intent(this, SimpleDecryptionActivity.class));
                return true;
            } else if (itemId == R.id.nav_advanced_decrypt) {
                startActivity(new Intent(this, AdvancedDecryptionActivity.class));
                return true;
            }
            return false;
        });
    }

    private String getFileName(Uri uri) {
        String result = null;
        if (uri.getScheme().equals("content")) {
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
