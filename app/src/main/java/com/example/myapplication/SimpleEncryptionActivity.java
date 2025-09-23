package com.example.myapplication;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.FileUtils;
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

public class SimpleEncryptionActivity extends AppCompatActivity implements CryptoListener {

    private static final int FILE_SELECT_CODE = 0;
    private Spinner modeSpinner;
    private EditText passwordInput;
    private Button fileSelectButton, encryptButton;
    private TextView selectedFileTextView;
    private ProgressBar progressBar;
    private ScrollView consoleScrollView;
    private TextView consoleTextView;
    private BottomNavigationView bottomNav;

    private Uri selectedFileUri;
    private CryptoManager cryptoManager;
    private String selectedMode = "Efficiency (Single-Thread)";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_simple_encryption);

        cryptoManager = new CryptoManager(this);

        modeSpinner = findViewById(R.id.mode_spinner);
        passwordInput = findViewById(R.id.password_input);
        fileSelectButton = findViewById(R.id.file_select_button);
        selectedFileTextView = findViewById(R.id.selected_file_textview);
        encryptButton = findViewById(R.id.encrypt_button);
        progressBar = findViewById(R.id.progress_bar);
        consoleScrollView = findViewById(R.id.console_scrollview);
        consoleTextView = findViewById(R.id.console_textview);
        bottomNav = findViewById(R.id.bottom_nav);

        setupSpinner();
        setupBottomNav();

        fileSelectButton.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
            intent.setType("*/*");
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            startActivityForResult(
                Intent.createChooser(intent, "Select a file to encrypt"),
                FILE_SELECT_CODE
            );
        });

        encryptButton.setOnClickListener(v -> {
            if (selectedFileUri == null) {
                onError("Please select a file first.");
                return;
            }
            String password = passwordInput.getText().toString();
            if (password.isEmpty()) {
                onError("Please enter a password.");
                return;
            }

            onLog("Encryption process started in " + selectedMode + " mode...");
            progressBar.setProgress(0);
            progressBar.setMax(100);

            new Thread(() -> {
                try {
                    File inputFile = new File(getCacheDir(), "tmp_" + getFileName(selectedFileUri));
                    try (InputStream is = getContentResolver().openInputStream(selectedFileUri);
                         OutputStream os = new FileOutputStream(inputFile)) {
                        byte[] buffer = new byte[8192];
                        int bytesRead;
                        while ((bytesRead = is.read(buffer)) != -1) {
                            os.write(buffer, 0, bytesRead);
                        }
                    }
                    
                    File outputFile = new File(getCacheDir(), "encrypted_" + inputFile.getName());

                    if ("Performance (Pipeline)".equals(selectedMode)) {
                        cryptoManager.encryptMultithreaded(password, inputFile.getAbsolutePath(), outputFile.getAbsolutePath());
                    } else {
                        cryptoManager.encrypt(password, inputFile.getAbsolutePath(), outputFile.getAbsolutePath());
                    }
                    
                    onLog("Output file location: " + outputFile.getAbsolutePath());

                } catch (Exception e) {
                    onError("Operation failed: " + e.getMessage());
                }
            }).start();
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
        bottomNav.setOnNavigationItemSelectedListener(item -> {
             int itemId = item.getItemId();
            if (itemId == R.id.nav_simple_encrypt) {
                return true;
            } else if (itemId == R.id.nav_advanced_encrypt) {
                startActivity(new Intent(this, AdvancedEncryptionActivity.class));
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
        if (requestCode == FILE_SELECT_CODE && resultCode == RESULT_OK && data != null) {
            selectedFileUri = data.getData();
            String fileName = getFileName(selectedFileUri);
            selectedFileTextView.setText("Selected file: " + fileName);
            onLog("File selected: " + fileName);
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
        } else if (uri.getScheme().equals("file")) {
            result = new File(uri.getPath()).getName();
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
    public void onProgress(float progress) {
        runOnUiThread(() -> {
            // Scale progress to 0-100 for the ProgressBar
            progressBar.setProgress((int) progress);
             // Also update a text view to show decimal progress if you want
            // For example: progressTextView.setText(String.format("%.2f%%", progress));
        });
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
