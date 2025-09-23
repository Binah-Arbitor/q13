package com.example.myapplication;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.FileUtils;
import android.provider.OpenableColumns;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import com.example.myapplication.crypto.CryptoListener;
import com.example.myapplication.crypto.CryptoManager;
import com.google.android.material.bottomnavigation.BottomNavigationView;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

public class AdvancedEncryptionActivity extends AppCompatActivity implements CryptoListener {

    private static final int PUBLIC_KEY_SELECT_CODE = 2;
    private static final int PRIVATE_KEY_SELECT_CODE = 3;
    private static final int FILE_SELECT_CODE = 4;

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

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_advanced_encryption);

        cryptoManager = new CryptoManager(this);

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

        publicKeySelectButton.setOnClickListener(v -> selectFile(PUBLIC_KEY_SELECT_CODE, "Select Public Key"));
        privateKeySelectButton.setOnClickListener(v -> selectFile(PRIVATE_KEY_SELECT_CODE, "Select Private Key"));
        fileSelectButton.setOnClickListener(v -> selectFile(FILE_SELECT_CODE, "Select File to Encrypt"));

        encryptButton.setOnClickListener(v -> {
            if (publicKeyUri == null || selectedFileUri == null) {
                onError("Public key and file to encrypt must be selected.");
                return;
            }
            boolean isSign = signCheckBox.isChecked();
            if (isSign && (privateKeyUri == null || passphraseInput.getText().toString().isEmpty())) {
                onError("Private key and passphrase are required for signing.");
                return;
            }

            onLog("PGP encryption process started...");
            progressBar.setProgress(0);

            new Thread(() -> {
                try {
                    // Create temporary files from Uris to get absolute paths
                    File publicKeyFile = createTempFileFromUri(publicKeyUri, "publicKey");
                    File inputFile = createTempFileFromUri(selectedFileUri, "inputFile");
                    File privateKeyFile = isSign ? createTempFileFromUri(privateKeyUri, "privateKey") : null;
                    
                    File outputFile = new File(getCacheDir(), "encrypted_" + inputFile.getName() + ".pgp");

                    cryptoManager.encryptPGP(
                        publicKeyFile.getAbsolutePath(),
                        isSign ? privateKeyFile.getAbsolutePath() : null,
                        passphraseInput.getText().toString(),
                        inputFile.getAbsolutePath(),
                        outputFile.getAbsolutePath(),
                        isSign
                    );

                    onLog("PGP encrypted file saved at: " + outputFile.getAbsolutePath());

                } catch (Exception e) {
                    onError("PGP Encryption failed: " + e.getMessage());
                }
            }).start();
        });
    }

    private File createTempFileFromUri(Uri uri, String prefix) throws Exception {
        File tempFile = File.createTempFile(prefix, "_" + getFileName(uri), getCacheDir());
        try (InputStream is = getContentResolver().openInputStream(uri);
             OutputStream os = new FileOutputStream(tempFile)) {
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
                FileUtils.copy(is, os);
            }
        }
        return tempFile;
    }

    private void selectFile(int requestCode, String title) {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("*/*");
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        startActivityForResult(Intent.createChooser(intent, title), requestCode);
    }

    private void setupBottomNav() {
        bottomNav.setSelectedItemId(R.id.nav_advanced_encrypt);
        bottomNav.setOnNavigationItemSelectedListener(item -> {
            int itemId = item.getItemId();
            if (itemId == R.id.nav_simple_encrypt) {
                startActivity(new Intent(this, SimpleEncryptionActivity.class));
                return true;
            } else if (itemId == R.id.nav_advanced_encrypt) {
                // Already here
                return true;
            } else if (itemId == R.id.nav_decrypt) {
                startActivity(new Intent(this, DecryptActivity.class));
                return true;
            }
            return false;
        });
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode == RESULT_OK && data != null) {
            Uri uri = data.getData();
            String fileName = getFileName(uri);
            switch (requestCode) {
                case PUBLIC_KEY_SELECT_CODE:
                    publicKeyUri = uri;
                    publicKeyTextView.setText("Public Key: " + fileName);
                    break;
                case PRIVATE_KEY_SELECT_CODE:
                    privateKeyUri = uri;
                    privateKeyTextView.setText("Private Key: " + fileName);
                    break;
                case FILE_SELECT_CODE:
                    selectedFileUri = uri;
                    selectedFileTextView.setText("File: " + fileName);
                    break;
            }
        }
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
