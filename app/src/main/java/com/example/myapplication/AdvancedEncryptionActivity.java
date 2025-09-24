package com.example.myapplication;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
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
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import com.example.myapplication.crypto.CryptoListener;
import com.example.myapplication.crypto.CryptoManager;
import com.google.android.material.bottomnavigation.BottomNavigationView;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

public class AdvancedEncryptionActivity extends AppCompatActivity implements CryptoListener {

    private Button publicKeySelectButton, privateKeySelectButton, fileSelectButton, encryptButton;
    private TextView publicKeyTextView, privateKeyTextView, selectedFileTextView;
    private EditText passphraseInput;
    private CheckBox signCheckBox;
    private ProgressBar progressBar;
    private ScrollView consoleScrollView;
    private TextView consoleTextView;
    private BottomNavigationView bottomNav;

    private Uri publicKeyUri, privateKeyUri, selectedFileUri;
    private CryptoManager cryptoManager;

    private ActivityResultLauncher<Intent> publicKeyFilePickerLauncher;
    private ActivityResultLauncher<Intent> privateKeyFilePickerLauncher;
    private ActivityResultLauncher<Intent> fileToEncryptPickerLauncher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_advanced_encryption);

        cryptoManager = new CryptoManager();

        // Initialize launchers
        publicKeyFilePickerLauncher = createAndRegisterLauncher(publicKeyTextView, "Public Key: ", uri -> publicKeyUri = uri);
        privateKeyFilePickerLauncher = createAndRegisterLauncher(privateKeyTextView, "Private Key: ", uri -> privateKeyUri = uri);
        fileToEncryptPickerLauncher = createAndRegisterLauncher(selectedFileTextView, "File: ", uri -> selectedFileUri = uri);

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
        consoleScrollView = findViewById(R.id.console_scrollview);
        consoleTextView = findViewById(R.id.console_textview);
        bottomNav = findViewById(R.id.bottom_nav);

        setupBottomNav();

        publicKeySelectButton.setOnClickListener(v -> launchFilePicker(publicKeyFilePickerLauncher, "Select Public Key"));
        privateKeySelectButton.setOnClickListener(v -> launchFilePicker(privateKeyFilePickerLauncher, "Select Private Key"));
        fileSelectButton.setOnClickListener(v -> launchFilePicker(fileToEncryptPickerLauncher, "Select File to Encrypt"));

        encryptButton.setOnClickListener(v -> handleEncryption());
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
        if (selectedFileUri == null || publicKeyUri == null) {
            onError("Please select a file and a public key.");
            return;
        }

        boolean shouldSign = signCheckBox.isChecked();
        if (shouldSign && privateKeyUri == null) {
            onError("Please select a private key for signing.");
            return;
        }

        String passphrase = passphraseInput.getText().toString();
        if (shouldSign && passphrase.isEmpty()) {
            onError("Please enter a passphrase for the private key.");
            return;
        }

        // Show progress bar and clear console
        progressBar.setVisibility(View.VISIBLE);
        consoleTextView.setText("");
        onLog("Starting encryption...");

        new Thread(() -> {
            try {
                // 1. Encrypt to a temporary in-memory buffer first
                onLog("Encrypting data to memory buffer...");
                InputStream inputStream = getContentResolver().openInputStream(selectedFileUri);
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();

                // Determine if we are signing or just encrypting
                if (shouldSign) {
                    onLog("Encryption with signing selected.");
                    cryptoManager.encryptAndSign(this, publicKeyUri, privateKeyUri, passphrase, inputStream, buffer);
                } else {
                    onLog("Encryption only selected.");
                    cryptoManager.encrypt(this, publicKeyUri, inputStream, buffer);
                }

                // 2. If encryption is successful, write the buffer to the original file
                onLog("Encryption successful. Writing to destination file...");
                try (OutputStream outputStream = getContentResolver().openOutputStream(selectedFileUri, "wt")) {
                    if (outputStream == null) {
                        throw new Exception("Failed to open output stream for the file.");
                    }
                    buffer.writeTo(outputStream);
                }

                onSuccess("File encrypted successfully and overwritten.");

            } catch (Exception e) {
                onError("Encryption failed: " + e.getMessage());
            } finally {
                runOnUiThread(() -> progressBar.setVisibility(View.GONE));
            }
        }).start();
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
            int cut = result.lastIndexOf('/');
            if (cut != -1) {
                result = result.substring(cut + 1);
            }
        }
        return result;
    }

    @Override
    public void onProgress(int progress) {
        runOnUiThread(() -> progressBar.setProgress(progress));
    }

    @Override
    public void onSuccess(String result) {
        runOnUiThread(() -> {
            consoleTextView.append("\n[SUCCESS] " + result + "\n");
            scrollToBottom();
            Toast.makeText(this, "Operation Successful", Toast.LENGTH_SHORT).show();
        });
    }

    @Override
    public void onError(String errorMessage) {
        runOnUiThread(() -> {
            consoleTextView.append("\n[ERROR] " + errorMessage + "\n");
            scrollToBottom();
            Toast.makeText(this, "Error: " + errorMessage, Toast.LENGTH_LONG).show();
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
