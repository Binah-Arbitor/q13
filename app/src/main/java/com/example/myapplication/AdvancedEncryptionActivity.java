package com.example.myapplication;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.SeekBar;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.core.content.ContextCompat;
import com.example.myapplication.crypto.CipherInfo;
import com.example.myapplication.crypto.CryptoListener;
import com.example.myapplication.crypto.CryptoManager;
import com.example.myapplication.crypto.CryptoOptions;
import com.google.android.material.bottomnavigation.BottomNavigationView;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;
import java.util.Locale;

public class AdvancedEncryptionActivity extends BaseActivity implements CryptoListener {

    // UI Elements
    private Spinner protocolSpinner, keyLengthSpinner, modeSpinner, paddingSpinner, kdfSpinner;
    private SeekBar chunkSizeSlider, threadCountSlider;
    private TextView chunkSizeValueTextView, threadCountValueTextView;
    private EditText passwordInput;
    private Button fileSelectButton, encryptButton;
    private TextView selectedFileTextView, statusTextView;
    private ProgressBar progressBar;
    private ScrollView consoleScrollView;
    private TextView consoleTextView;
    private BottomNavigationView bottomNav;

    // State
    private Uri selectedFileUri;
    private CryptoManager cryptoManager;
    private int lastProgress = -1;
    private int currentChunkSizeKb = 4; // Default chunk size
    private int currentThreadCount = 1;

    private ActivityResultLauncher<Intent> filePickerLauncher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_advanced_encryption);
        getSupportActionBar().setTitle("Advanced Encryption");

        cryptoManager = new CryptoManager(this, getApplicationContext());

        initializeViews();
        setupLaunchers();
        setupSpinners();
        setupSliders();
        setupBottomNav();

        fileSelectButton.setOnClickListener(v -> checkPermissionsAndExecute(this::launchFilePicker));
        encryptButton.setOnClickListener(v -> handleEncryption());
    }

    @Override
    protected void onResume() {
        super.onResume();
        // Set the selected item in the bottom navigation view
        if (bottomNav != null) {
            bottomNav.setSelectedItemId(R.id.nav_advanced_encrypt);
        }
    }

    @Override
    protected boolean isActivityForAdvancedMode() {
        return true;
    }

    private void initializeViews() {
        // Spinners
        protocolSpinner = findViewById(R.id.protocol_spinner);
        keyLengthSpinner = findViewById(R.id.key_length_spinner);
        modeSpinner = findViewById(R.id.mode_spinner);
        paddingSpinner = findViewById(R.id.padding_spinner);
        kdfSpinner = findViewById(R.id.kdf_spinner);

        // Sliders and their value displays
        chunkSizeSlider = findViewById(R.id.chunk_size_slider);
        threadCountSlider = findViewById(R.id.thread_count_slider);
        chunkSizeValueTextView = findViewById(R.id.chunk_size_value_textview);
        threadCountValueTextView = findViewById(R.id.thread_count_value_textview);

        // Other UI components
        passwordInput = findViewById(R.id.password_input);
        fileSelectButton = findViewById(R.id.file_select_button);
        encryptButton = findViewById(R.id.encrypt_button);
        selectedFileTextView = findViewById(R.id.selected_file_textview);
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
                        final int takeFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION;
                        getContentResolver().takePersistableUriPermission(selectedFileUri, takeFlags);

                        String fileName = getFileName(selectedFileUri);
                        selectedFileTextView.setText("Selected file: " + fileName);
                        onLog("File selected: " + fileName);
                    }
                }
            }
        );
    }

    private void setupSpinners() {
        ArrayAdapter<String> protocolAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, CipherInfo.getSupportedCiphers());
        protocolSpinner.setAdapter(protocolAdapter);

        updateKeyLengthSpinner();
        updateModeAndPaddingSpinners();

        ArrayAdapter<String> kdfAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, CipherInfo.getSupportedKdfs());
        kdfSpinner.setAdapter(kdfAdapter);

        protocolSpinner.setOnItemSelectedListener(new SimpleItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                updateKeyLengthSpinner();
            }
        });

        modeSpinner.setOnItemSelectedListener(new SimpleItemSelectedListener() {
             @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                updatePaddingSpinner();
            }
        });
    }
    
    private void updateKeyLengthSpinner() {
        String selectedCipher = protocolSpinner.getSelectedItem().toString();
        List<Integer> keyLengths = CipherInfo.getValidKeyLengths(selectedCipher);
        ArrayAdapter<Integer> keyLengthAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, keyLengths);
        keyLengthSpinner.setAdapter(keyLengthAdapter);
    }

    private void updateModeAndPaddingSpinners() {
        ArrayAdapter<String> modeAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, CipherInfo.getSupportedModes());
        modeSpinner.setAdapter(modeAdapter);
        updatePaddingSpinner();
    }

    private void updatePaddingSpinner() {
        String selectedMode = modeSpinner.getSelectedItem().toString();
        ArrayAdapter<String> paddingAdapter;
        if (CipherInfo.isStreamMode(selectedMode)) {
            paddingAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, new String[]{"NoPadding"});
            paddingSpinner.setEnabled(false);
        } else {
            paddingAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, CipherInfo.getSupportedPaddings());
            paddingSpinner.setEnabled(true);
        }
        paddingSpinner.setAdapter(paddingAdapter);
    }

    private void setupSliders() {
        chunkSizeSlider.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
            @Override
            public void onProgressChanged(SeekBar seekBar, int progress, boolean fromUser) {
                currentChunkSizeKb = 4 * (int) Math.pow(2, progress);
                if (currentChunkSizeKb < 1024) {
                    chunkSizeValueTextView.setText(String.format(Locale.US, "%d KB", currentChunkSizeKb));
                } else {
                    chunkSizeValueTextView.setText(String.format(Locale.US, "%d MB", currentChunkSizeKb / 1024));
                }
            }
            @Override public void onStartTrackingTouch(SeekBar seekBar) {} 
            @Override public void onStopTrackingTouch(SeekBar seekBar) {}  
        });
        chunkSizeValueTextView.setText("4 KB");

        int maxThreads = Math.max(1, Runtime.getRuntime().availableProcessors());
        threadCountSlider.setMax(maxThreads - 1);
        threadCountSlider.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
            @Override
            public void onProgressChanged(SeekBar seekBar, int progress, boolean fromUser) {
                currentThreadCount = progress + 1;
                threadCountValueTextView.setText(String.format(Locale.US, "%d", currentThreadCount));
            }
            @Override public void onStartTrackingTouch(SeekBar seekBar) {} 
            @Override public void onStopTrackingTouch(SeekBar seekBar) {}  
        });
        threadCountValueTextView.setText("1");
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

        try {
            String protocol = protocolSpinner.getSelectedItem().toString();
            int keyLength = (Integer) keyLengthSpinner.getSelectedItem();
            String mode = modeSpinner.getSelectedItem().toString();
            String padding = paddingSpinner.getSelectedItem().toString();
            String kdf = kdfSpinner.getSelectedItem().toString();
            int chunkSize = currentChunkSizeKb * 1024;
            int threadCount = currentThreadCount;

            CryptoOptions options = new CryptoOptions(protocol, keyLength, mode, padding, kdf, chunkSize, threadCount);
            onLog("Crypto Options: " + options.toString());

            long totalSize;
            try (ParcelFileDescriptor pfd = getContentResolver().openFileDescriptor(selectedFileUri, "r")) {
                totalSize = pfd.getStatSize();
            }
            InputStream inputStream = getContentResolver().openInputStream(selectedFileUri);
            OutputStream outputStream = getContentResolver().openOutputStream(selectedFileUri, "wt");

            if (inputStream == null || outputStream == null) {
                throw new Exception("Failed to open streams for the selected file.");
            }

            setUiEnabled(false);
            onLog("Starting advanced encryption...");

            cryptoManager.encryptAdvanced(password, inputStream, totalSize, outputStream, options);

        } catch (Exception e) {
            onError("Failed to start encryption: " + e.getMessage());
            setUiEnabled(true);
        }
    }


    private void setUiEnabled(boolean enabled) {
        runOnUiThread(() -> {
            encryptButton.setEnabled(enabled);
            fileSelectButton.setEnabled(enabled);
            protocolSpinner.setEnabled(enabled);
            keyLengthSpinner.setEnabled(enabled);
            modeSpinner.setEnabled(enabled);
            paddingSpinner.setEnabled(enabled);
            kdfSpinner.setEnabled(enabled);
            chunkSizeSlider.setEnabled(enabled);
            threadCountSlider.setEnabled(enabled);
            passwordInput.setEnabled(enabled);

            if (enabled) {
                progressBar.setVisibility(View.GONE);
                statusTextView.setVisibility(View.GONE);
            } else {
                lastProgress = -1;
                progressBar.setVisibility(View.VISIBLE);
                progressBar.setProgress(0);
                statusTextView.setVisibility(View.GONE);
            }
        });
    }

    private void setupBottomNav() {
        bottomNav.setOnItemSelectedListener(item -> {
            int itemId = item.getItemId();
            if (itemId == R.id.nav_advanced_encrypt) {
                // Already here
            } else if (itemId == R.id.nav_advanced_decrypt) {
                Intent intent = new Intent(this, AdvancedDecryptionActivity.class);
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
    
    private static abstract class SimpleItemSelectedListener implements AdapterView.OnItemSelectedListener {
        @Override public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {}
        @Override public void onNothingSelected(AdapterView<?> parent) {} 
    }
}
