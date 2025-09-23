package com.example.myapplication;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.FileUtils;
import android.provider.OpenableColumns;
import android.widget.Button;
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

public class DecryptActivity extends AppCompatActivity implements CryptoListener {

    private static final int FILE_SELECT_CODE = 1;
    private EditText passwordInput;
    private Button fileSelectButton, decryptButton;
    private TextView selectedFileTextView;
    private ProgressBar progressBar;
    private ScrollView consoleScrollView;
    private TextView consoleTextView;
    private BottomNavigationView bottomNav;

    private Uri selectedFileUri;
    private CryptoManager cryptoManager;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_decrypt);

        cryptoManager = new CryptoManager(this);

        passwordInput = findViewById(R.id.password_input);
        fileSelectButton = findViewById(R.id.file_select_button);
        selectedFileTextView = findViewById(R.id.selected_file_textview);
        decryptButton = findViewById(R.id.decrypt_button);
        progressBar = findViewById(R.id.progress_bar);
        consoleScrollView = findViewById(R.id.console_scrollview);
        consoleTextView = findViewById(R.id.console_textview);
        bottomNav = findViewById(R.id.bottom_nav);

        setupBottomNav();

        fileSelectButton.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
            intent.setType("*/*");
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            startActivityForResult(
                Intent.createChooser(intent, "Select a file to decrypt"),
                FILE_SELECT_CODE
            );
        });

        decryptButton.setOnClickListener(v -> {
            if (selectedFileUri == null) {
                onError("Please select a file first.");
                return;
            }
            String password = passwordInput.getText().toString();
            if (password.isEmpty()) {
                onError("Please enter a password.");
                return;
            }

            onLog("Decryption process started...");
            progressBar.setProgress(0);
            
            // Run decryption in a background thread.
            new Thread(() -> {
                try {
                    File inputFile = new File(getCacheDir(), getFileName(selectedFileUri));
                    try (InputStream is = getContentResolver().openInputStream(selectedFileUri);
                         OutputStream os = new FileOutputStream(inputFile)) {
                        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
                            FileUtils.copy(is, os);
                        }
                    }
                    
                    File outputFile = new File(getCacheDir(), "decrypted_" + inputFile.getName().replace("encrypted_", ""));

                    cryptoManager.decrypt(password, inputFile.getAbsolutePath(), outputFile.getAbsolutePath());
                    
                    onLog("Decrypted file saved at: " + outputFile.getAbsolutePath());

                } catch (Exception e) {
                    onError("Decryption failed: " + e.getMessage());
                }
            }).start();
        });
    }

    private void setupBottomNav() {
        bottomNav.setSelectedItemId(R.id.nav_decrypt); // Set the selected item
        bottomNav.setOnNavigationItemSelectedListener(item -> {
            int itemId = item.getItemId();
            if (itemId == R.id.nav_simple_encrypt) {
                startActivity(new Intent(this, SimpleEncryptionActivity.class));
                return true;
            } else if (itemId == R.id.nav_advanced_encrypt) {
                startActivity(new Intent(this, AdvancedEncryptionActivity.class));
                return true;
            } else if (itemId == R.id.nav_decrypt) {
                // Already here
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
            Toast.makeText(this, "Decryption Successful", Toast.LENGTH_SHORT).show();
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
