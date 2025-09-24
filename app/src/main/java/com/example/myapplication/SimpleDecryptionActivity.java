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
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import com.example.myapplication.crypto.CryptoListener;
import com.example.myapplication.crypto.CryptoManager;
import com.google.android.material.bottomnavigation.BottomNavigationView;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

public class SimpleDecryptionActivity extends AppCompatActivity implements CryptoListener {

    private Spinner decryptionModeSpinner, threadModeSpinner;
    private EditText passwordInput;
    private Button fileSelectButton, decryptButton, privateKeySelectButton, signerPublicKeySelectButton;
    private TextView selectedFileTextView, privateKeyTextView, signerPublicKeyTextView, statusTextView;
    private ProgressBar progressBar;
    private ScrollView consoleScrollView;
    private TextView consoleTextView;
    private BottomNavigationView bottomNav;
    private LinearLayout pgpKeySelectionLayout;

    private Uri selectedFileUri, privateKeyUri, signerPublicKeyUri;
    private CryptoManager cryptoManager;

    private ActivityResultLauncher<Intent> fileToDecryptPickerLauncher;
    private ActivityResultLauncher<Intent> privateKeyFilePickerLauncher;
    private ActivityResultLauncher<Intent> signerPublicKeyFilePickerLauncher;

    private enum DecryptionMode { SIMPLE_AES, PGP }
    private DecryptionMode currentMode = DecryptionMode.SIMPLE_AES;
    private String currentThreadMode = "Efficiency (Single-Thread)";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_simple_decryption);

        cryptoManager = new CryptoManager(this);

        // Initialize launchers
        fileToDecryptPickerLauncher = createAndRegisterLauncher(selectedFileTextView, "File: ", uri -> selectedFileUri = uri);
        privateKeyFilePickerLauncher = createAndRegisterLauncher(privateKeyTextView, "Private Key: ", uri -> privateKeyUri = uri);
        signerPublicKeyFilePickerLauncher = createAndRegisterLauncher(signerPublicKeyTextView, "Signer Key: ", uri -> signerPublicKeyUri = uri);

        decryptionModeSpinner = findViewById(R.id.decryption_mode_spinner);
        threadModeSpinner = findViewById(R.id.thread_mode_spinner);
        passwordInput = findViewById(R.id.password_input);
        fileSelectButton = findViewById(R.id.file_select_button);
        decryptButton = findViewById(R.id.decrypt_button);
        privateKeySelectButton = findViewById(R.id.private_key_select_button);
        signerPublicKeySelectButton = findViewById(R.id.signer_public_key_select_button);
        selectedFileTextView = findViewById(R.id.selected_file_textview);
        privateKeyTextView = findViewById(R.id.private_key_textview);
        signerPublicKeyTextView = findViewById(R.id.signer_public_key_textview);
        pgpKeySelectionLayout = findViewById(R.id.pgp_key_selection_layout);
        progressBar = findViewById(R.id.progress_bar);
        statusTextView = findViewById(R.id.status_textview);
        consoleScrollView = findViewById(R.id.console_scrollview);
        consoleTextView = findViewById(R.id.console_textview);
        bottomNav = findViewById(R.id.bottom_nav);

        setupSpinners();
        setupBottomNav();

        fileSelectButton.setOnClickListener(v -> launchFilePicker(fileToDecryptPickerLauncher, "Select File to Decrypt"));
        privateKeySelectButton.setOnClickListener(v -> launchFilePicker(privateKeyFilePickerLauncher, "Select Private Key"));
        signerPublicKeySelectButton.setOnClickListener(v -> launchFilePicker(signerPublicKeyFilePickerLauncher, "Select Signer Public Key"));

        decryptButton.setOnClickListener(v -> handleDecryption());
        
        updateUiForMode(currentMode);
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

    private void handleDecryption() {
        if (selectedFileUri == null) {
            onError("Please select a file to decrypt.");
            return;
        }
        
        setUiEnabled(false);

        switch (currentMode) {
            case SIMPLE_AES:
                handleSimpleAesDecryption();
                break;
            case PGP:
                handlePgpDecryption();
                break;
        }
    }
    
    private void handleSimpleAesDecryption() {
        String password = passwordInput.getText().toString();
        if (password.isEmpty()) {
            onError("Please enter a password.");
            return;
        }
        
        final boolean useMultithreading = "Performance (Parallel)".equals(currentThreadMode);
        String modeLog = useMultithreading ? "Performance (Parallel)" : "Efficiency (Single-Thread)";
        onLog("Starting Simple AES decryption in " + modeLog + " mode...");
        
        new Thread(() -> {
            try {
                onLog("Verifying and decrypting data to memory buffer...");
                InputStream inputStream = getContentResolver().openInputStream(selectedFileUri);
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();

                cryptoManager.decrypt(password, inputStream, buffer, useMultithreading);

                onLog("Decryption successful. Overwriting original file...");
                try (OutputStream outputStream = getContentResolver().openOutputStream(selectedFileUri, "wt")) {
                    if (outputStream == null) throw new Exception("Failed to open output stream for the file.");
                    buffer.writeTo(outputStream);
                }
                onSuccess("File decrypted and overwritten successfully.");

            } catch (Exception e) {
                onError("Decryption failed: " + e.getMessage());
            }
        }).start();
    }
    
    private void handlePgpDecryption() {
        onError("PGP decryption is not yet implemented.");
    }

    private void setupSpinners() {
        String[] modes = {"Simple AES (Password)", "PGP (Keys)"};
        ArrayAdapter<String> modeAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, modes);
        decryptionModeSpinner.setAdapter(modeAdapter);
        decryptionModeSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                currentMode = (position == 0) ? DecryptionMode.SIMPLE_AES : DecryptionMode.PGP;
                updateUiForMode(currentMode);
            }
            @Override
            public void onNothingSelected(AdapterView<?> parent) { }
        });

        String[] threadModes = {"Efficiency (Single-Thread)", "Performance (Parallel)"};
        ArrayAdapter<String> threadAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, threadModes);
        threadModeSpinner.setAdapter(threadAdapter);
        threadModeSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                currentThreadMode = (String) parent.getItemAtPosition(position);
            }
            @Override
            public void onNothingSelected(AdapterView<?> parent) { }
        });
    }

    private void updateUiForMode(DecryptionMode mode) {
        if (mode == DecryptionMode.SIMPLE_AES) {
            passwordInput.setVisibility(View.VISIBLE);
            passwordInput.setHint("Password");
            pgpKeySelectionLayout.setVisibility(View.GONE);
            threadModeSpinner.setVisibility(View.VISIBLE);
        } else { // PGP
            passwordInput.setVisibility(View.VISIBLE);
            passwordInput.setHint("Passphrase for Private Key");
            pgpKeySelectionLayout.setVisibility(View.VISIBLE);
            threadModeSpinner.setVisibility(View.GONE);
        }
    }

    private void setUiEnabled(boolean enabled) {
        runOnUiThread(() -> {
            decryptButton.setEnabled(enabled);
            fileSelectButton.setEnabled(enabled);
            decryptionModeSpinner.setEnabled(enabled);
            threadModeSpinner.setEnabled(enabled);
            passwordInput.setEnabled(enabled);
            privateKeySelectButton.setEnabled(enabled);
            signerPublicKeySelectButton.setEnabled(enabled);

            if (enabled) {
                progressBar.setVisibility(View.GONE);
            } else {
                progressBar.setVisibility(View.VISIBLE);
                progressBar.setProgress(0);
                statusTextView.setVisibility(View.GONE);
            }
        });
    }

    private void setupBottomNav() {
        bottomNav.setSelectedItemId(R.id.nav_simple_decrypt);
        bottomNav.setOnNavigationItemSelectedListener(item -> {
            int itemId = item.getItemId();
            if (itemId == R.id.nav_simple_encrypt) {
                startActivity(new Intent(this, SimpleEncryptionActivity.class));
                return true;
            } else if (itemId == R.id.nav_advanced_encrypt) {
                startActivity(new Intent(this, AdvancedEncryptionActivity.class));
                return true;
            } else if (itemId == R.id.nav_simple_decrypt) {
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
        } catch (Exception e) {
            onLog("Error getting file name: " + e.getMessage());
            return null;
        }
        if (result == null) {
            result = uri.getPath();
            if(result == null) return null;
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
