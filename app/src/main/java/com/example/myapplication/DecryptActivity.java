package com.example.myapplication;

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
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import com.example.myapplication.crypto.CryptoListener;
import com.example.myapplication.crypto.CryptoManager;
import com.google.android.material.bottomnavigation.BottomNavigationView;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

public class DecryptActivity extends AppCompatActivity implements CryptoListener {

    private static final int FILE_SELECT_CODE = 1;
    private static final int PRIVATE_KEY_SELECT_CODE = 5;
    private static final int SIGNER_PUBLIC_KEY_SELECT_CODE = 6;

    private Spinner decryptionModeSpinner;
    private EditText passwordInput;
    private Button fileSelectButton, decryptButton, privateKeySelectButton, signerPublicKeySelectButton;
    private TextView selectedFileTextView, privateKeyTextView, signerPublicKeyTextView;
    private ProgressBar progressBar;
    private ScrollView consoleScrollView;
    private TextView consoleTextView;
    private BottomNavigationView bottomNav;

    private Uri selectedFileUri, privateKeyUri, signerPublicKeyUri;
    private CryptoManager cryptoManager;

    private enum DecryptionMode { AES, PGP } // Keep for UI logic
    private DecryptionMode currentMode = DecryptionMode.AES;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_decrypt);

        cryptoManager = new CryptoManager(this);

        decryptionModeSpinner = findViewById(R.id.decryption_mode_spinner);
        passwordInput = findViewById(R.id.password_input);
        fileSelectButton = findViewById(R.id.file_select_button);
        decryptButton = findViewById(R.id.decrypt_button);
        privateKeySelectButton = findViewById(R.id.private_key_select_button);
        signerPublicKeySelectButton = findViewById(R.id.signer_public_key_select_button);
        selectedFileTextView = findViewById(R.id.selected_file_textview);
        privateKeyTextView = findViewById(R.id.private_key_textview);
        signerPublicKeyTextView = findViewById(R.id.signer_public_key_textview);
        progressBar = findViewById(R.id.progress_bar);
        consoleScrollView = findViewById(R.id.console_scrollview);
        consoleTextView = findViewById(R.id.console_textview);
        bottomNav = findViewById(R.id.bottom_nav);

        setupSpinner();
        setupBottomNav();

        fileSelectButton.setOnClickListener(v -> selectFile(FILE_SELECT_CODE, "Select File to Decrypt"));
        privateKeySelectButton.setOnClickListener(v -> selectFile(PRIVATE_KEY_SELECT_CODE, "Select Private Key"));
        signerPublicKeySelectButton.setOnClickListener(v -> selectFile(SIGNER_PUBLIC_KEY_SELECT_CODE, "Select Signer Public Key"));

        decryptButton.setOnClickListener(v -> {
            if (selectedFileUri == null) {
                onError("Please select a file first.");
                return;
            }
            String password = passwordInput.getText().toString();

            if (currentMode == DecryptionMode.PGP) {
                onLog("PGP decryption is not yet implemented.");
                Toast.makeText(this, "Not Implemented Yet", Toast.LENGTH_SHORT).show();
                return;
            }

            // Default to AES Decryption
            if (password.isEmpty()) {
                onError("Password is required for AES decryption.");
                return;
            }
            
            onLog("AES Decryption process started...");
            progressBar.setProgress(0);

            new Thread(() -> {
                try {
                    File inputFile = createTempFileFromUri(selectedFileUri, "inputFile");
                    String outputFileName = "decrypted_" + getFileName(selectedFileUri);
                    File outputFile = new File(getCacheDir(), outputFileName);
                    
                    cryptoManager.decrypt(password, inputFile.getAbsolutePath(), outputFile.getAbsolutePath());
                    
                    onLog("Decrypted file saved at: " + outputFile.getAbsolutePath());

                } catch (Exception e) {
                    onError("Decryption failed: " + e.getMessage());
                }
            }).start();
        });
    }
    
    private File createTempFileFromUri(Uri uri, String prefix) throws Exception {
        File tempFile = File.createTempFile(prefix, "_" + getFileName(uri), getCacheDir());
        try (InputStream is = getContentResolver().openInputStream(uri);
             OutputStream os = new FileOutputStream(tempFile)) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while((bytesRead = is.read(buffer)) != -1) {
                os.write(buffer, 0, bytesRead);
            }
        }
        return tempFile;
    }

    private void setupSpinner() {
        String[] modes = {"Simple AES", "PGP"};
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, modes);
        decryptionModeSpinner.setAdapter(adapter);
        decryptionModeSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                currentMode = position == 0 ? DecryptionMode.AES : DecryptionMode.PGP;
                updateUiForMode(currentMode);
            }
            @Override
            public void onNothingSelected(AdapterView<?> parent) { }
        });
    }

    private void updateUiForMode(DecryptionMode mode) {
        if (mode == DecryptionMode.AES) {
            privateKeySelectButton.setVisibility(View.GONE);
            privateKeyTextView.setVisibility(View.GONE);
            signerPublicKeySelectButton.setVisibility(View.GONE);
            signerPublicKeyTextView.setVisibility(View.GONE);
            passwordInput.setHint("Password");
        } else { // PGP
            privateKeySelectButton.setVisibility(View.VISIBLE);
            privateKeyTextView.setVisibility(View.VISIBLE);
            signerPublicKeySelectButton.setVisibility(View.VISIBLE);
            signerPublicKeyTextView.setVisibility(View.VISIBLE);
            passwordInput.setHint("Passphrase");
        }
    }

    private void selectFile(int requestCode, String title) {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("*/*");
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        startActivityForResult(Intent.createChooser(intent, title), requestCode);
    }

    private void setupBottomNav() {
        bottomNav.setSelectedItemId(R.id.nav_decrypt);
        bottomNav.setOnNavigationItemSelectedListener(item -> {
            int itemId = item.getItemId();
            if (itemId == R.id.nav_simple_encrypt) {
                startActivity(new Intent(this, SimpleEncryptionActivity.class));
                return true;
            } else if (itemId == R.id.nav_advanced_encrypt) {
                startActivity(new Intent(this, AdvancedEncryptionActivity.class));
                return true;
            } else if (itemId == R.id.nav_decrypt) {
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
                case FILE_SELECT_CODE:
                    selectedFileUri = uri;
                    selectedFileTextView.setText("File: " + fileName);
                    break;
                case PRIVATE_KEY_SELECT_CODE:
                    privateKeyUri = uri;
                    privateKeyTextView.setText("Private Key: " + fileName);
                    break;
                case SIGNER_PUBLIC_KEY_SELECT_CODE:
                    signerPublicKeyUri = uri;
                    signerPublicKeyTextView.setText("Signer Key: " + fileName);
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
