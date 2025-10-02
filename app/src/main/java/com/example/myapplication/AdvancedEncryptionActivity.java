package com.example.myapplication;

import android.content.ContentResolver;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
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
import androidx.appcompat.app.AppCompatActivity;

import com.example.myapplication.crypto.CryptoListener;
import com.example.myapplication.crypto.CryptoManager;
import com.example.myapplication.crypto.CryptoOptions;
import com.google.android.material.bottomnavigation.BottomNavigationView;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

public class AdvancedEncryptionActivity extends AppCompatActivity implements CryptoListener {

    private Spinner protocolSpinner, keyLengthSpinner, blockSpinner, modeSpinner, paddingSpinner, kdfSpinner;
    private SeekBar threadCountSlider, chunkSizeSlider;
    private TextView threadCountValueTextView, chunkSizeValueTextView;
    private EditText passwordInput;
    private Button fileSelectButton, encryptButton;
    private TextView selectedFileTextView, consoleTextView, statusTextView;
    private ProgressBar progressBar;
    private ScrollView consoleScrollView;
    private View blockSpinnerLabel;
    private BottomNavigationView bottomNav;

    private Uri selectedFileUri;
    private String sourcePathForTempFile; // To keep track of the temporary file
    private final CryptoManager cryptoManager = new CryptoManager();
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private ActivityResultLauncher<Intent> filePickerLauncher;
    private static final int[] CHUNK_SIZES_KB = {4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384};

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_advanced_encryption);
        setTitle("Advanced Encryption");

        initializeViews();
        setupFilePicker();
        setupSpinners();
        setupEventListeners();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.main_overflow_menu, menu);
        MenuItem switchItem = menu.findItem(R.id.action_switch_mode);
        switchItem.setTitle("Switch to Simple");
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int itemId = item.getItemId();
        if (itemId == R.id.action_switch_mode) {
            Intent intent = new Intent(AdvancedEncryptionActivity.this, SimpleEncryptionActivity.class);
            startActivity(intent);
            finish();
            return true;
        } else if (itemId == R.id.action_license) {
            Intent intent = new Intent(AdvancedEncryptionActivity.this, LicenseActivity.class);
            startActivity(intent);
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void initializeViews() {
        protocolSpinner = findViewById(R.id.protocol_spinner);
        keyLengthSpinner = findViewById(R.id.key_length_spinner);
        blockSpinner = findViewById(R.id.block_size_spinner);
        blockSpinnerLabel = findViewById(R.id.block_size_label);
        modeSpinner = findViewById(R.id.mode_spinner);
        paddingSpinner = findViewById(R.id.padding_spinner);
        kdfSpinner = findViewById(R.id.kdf_spinner);
        threadCountSlider = findViewById(R.id.thread_count_slider);
        threadCountValueTextView = findViewById(R.id.thread_count_value_textview);
        chunkSizeSlider = findViewById(R.id.chunk_size_slider);
        chunkSizeValueTextView = findViewById(R.id.chunk_size_value_textview);
        passwordInput = findViewById(R.id.password_input);
        fileSelectButton = findViewById(R.id.file_select_button);
        encryptButton = findViewById(R.id.encrypt_button);
        selectedFileTextView = findViewById(R.id.selected_file_textview);
        progressBar = findViewById(R.id.progress_bar);
        consoleTextView = findViewById(R.id.console_textview);
        consoleScrollView = findViewById(R.id.console_scrollview);
        statusTextView = findViewById(R.id.status_textview);
        bottomNav = findViewById(R.id.bottom_nav);
    }

    private void setupFilePicker() {
        filePickerLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == RESULT_OK && result.getData() != null) {
                        selectedFileUri = result.getData().getData();
                        String fileName = getFileName(selectedFileUri);
                        selectedFileTextView.setText(fileName != null ? fileName : "No file selected");
                    }
                });
    }

    private void setupSpinners() {
        ArrayAdapter<CryptoOptions.CryptoProtocol> protocolAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, CryptoOptions.CryptoProtocol.values());
        protocolAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        protocolSpinner.setAdapter(protocolAdapter);

        ArrayAdapter<CryptoOptions.Kdf> kdfAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, CryptoOptions.Kdf.values());
        kdfAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        kdfSpinner.setAdapter(kdfAdapter);

        protocolSpinner.setSelection(0);
        kdfSpinner.setSelection(0);
    }

    private void setupEventListeners() {
        protocolSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                updateDependantSpinners();
            }
            @Override public void onNothingSelected(AdapterView<?> parent) {}
        });

        keyLengthSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                 updateModeSpinner();
            }
            @Override public void onNothingSelected(AdapterView<?> parent) { }
        });

        modeSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                updatePaddingSpinner();
            }
            @Override public void onNothingSelected(AdapterView<?> parent) {}
        });

        fileSelectButton.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            intent.setType("*/*");
            filePickerLauncher.launch(intent);
        });

        encryptButton.setOnClickListener(v -> handleEncryption());

        bottomNav.setOnItemSelectedListener(item -> {
            int itemId = item.getItemId();
            if (itemId == R.id.nav_advanced_decrypt) {
                Intent intent = new Intent(AdvancedEncryptionActivity.this, AdvancedDecryptionActivity.class);
                startActivity(intent);
                finish();
                return true;
            } else if (itemId == R.id.nav_advanced_encrypt) {
                return true; // Do nothing
            }
            return false;
        });
        bottomNav.setSelectedItemId(R.id.nav_advanced_encrypt);

        int maxThreads = Math.max(1, Runtime.getRuntime().availableProcessors() * 2);
        threadCountSlider.setMax(maxThreads - 1);
        threadCountSlider.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
            @Override
            public void onProgressChanged(SeekBar seekBar, int progress, boolean fromUser) {
                threadCountValueTextView.setText(String.valueOf(progress + 1));
            }
            @Override public void onStartTrackingTouch(SeekBar seekBar) {} 
            @Override public void onStopTrackingTouch(SeekBar seekBar) {}
        });
        threadCountSlider.setProgress(0);
        threadCountValueTextView.setText("1");

        chunkSizeSlider.setMax(CHUNK_SIZES_KB.length - 1);
        chunkSizeSlider.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
            @Override
            public void onProgressChanged(SeekBar seekBar, int progress, boolean fromUser) {
                chunkSizeValueTextView.setText(CHUNK_SIZES_KB[progress] + " KB");
            }
            @Override public void onStartTrackingTouch(SeekBar seekBar) {}
            @Override public void onStopTrackingTouch(SeekBar seekBar) {}
        });
        chunkSizeSlider.setProgress(0);
        chunkSizeValueTextView.setText(CHUNK_SIZES_KB[0] + " KB");
    }
    
    private void updateDependantSpinners() {
        updateKeyLengthSpinner();
        updateBlockSizeSpinner();
    }
    
    private void updateKeyLengthSpinner() {
        CryptoOptions.CryptoProtocol selectedProtocol = (CryptoOptions.CryptoProtocol) protocolSpinner.getSelectedItem();
        if (selectedProtocol == null) return;
        
        ArrayAdapter<CryptoOptions.KeyLength> keyLengthAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, selectedProtocol.getSupportedKeyLengths());
        keyLengthAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        keyLengthSpinner.setAdapter(keyLengthAdapter);
    }

    private void updateBlockSizeSpinner() {
        CryptoOptions.CryptoProtocol selectedProtocol = (CryptoOptions.CryptoProtocol) protocolSpinner.getSelectedItem();
        if (selectedProtocol == null) return;

        List<Integer> supportedBlockSizes = selectedProtocol.getSupportedBlockBits();
        ArrayAdapter<Integer> blockAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, supportedBlockSizes);
        blockAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        blockSpinner.setAdapter(blockAdapter);

        boolean isVisible = !supportedBlockSizes.isEmpty();
        blockSpinner.setVisibility(isVisible ? View.VISIBLE : View.GONE);
        blockSpinnerLabel.setVisibility(isVisible ? View.VISIBLE : View.GONE);

        if (isVisible) {
            blockSpinner.setSelection(0);
        }
        updateModeSpinner();
    }

    private void updateModeSpinner() {
        CryptoOptions.CryptoProtocol selectedProtocol = (CryptoOptions.CryptoProtocol) protocolSpinner.getSelectedItem();
        if (selectedProtocol == null) return;

        CryptoOptions.KeyLength selectedKeyLength = (CryptoOptions.KeyLength) keyLengthSpinner.getSelectedItem();
        if (selectedKeyLength == null) return;

        List<CryptoOptions.CipherMode> supportedModes = selectedProtocol.getSupportedModes();
        
        List<CryptoOptions.CipherMode> modes = supportedModes.stream()
                .filter(m -> selectedProtocol.isModeSupported(m))
                .collect(Collectors.toList());

        ArrayAdapter<CryptoOptions.CipherMode> modeAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, modes);
        modeAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        modeSpinner.setAdapter(modeAdapter);
        if (!modes.isEmpty()) {
            modeSpinner.setSelection(0);
        }
        updatePaddingSpinner();
    }

    private void updatePaddingSpinner() {
        Object selectedItem = modeSpinner.getSelectedItem();
        if (selectedItem == null) {
            paddingSpinner.setAdapter(null);
            paddingSpinner.setEnabled(false);
            return;
        }

        CryptoOptions.CipherMode selectedMode = (CryptoOptions.CipherMode) selectedItem;
        boolean isStreamCipher = selectedMode.isStreamMode();

        if (isStreamCipher) {
            ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, new String[]{"NoPadding"});
            paddingSpinner.setAdapter(adapter);
            paddingSpinner.setEnabled(false);
        } else {
            ArrayAdapter<CryptoOptions.Padding> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, CryptoOptions.Padding.values());
            adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
            paddingSpinner.setAdapter(adapter);
            paddingSpinner.setEnabled(true);
        }
    }

    private void handleEncryption() {
        if (selectedFileUri == null) {
            onError("Please select a file.", null);
            return;
        }
        char[] password = passwordInput.getText().toString().toCharArray();
        if (password.length == 0) {
            onError("Password cannot be empty.", null);
            return;
        }

        try {
            CryptoOptions.CryptoProtocol protocol = (CryptoOptions.CryptoProtocol) protocolSpinner.getSelectedItem();
            CryptoOptions.KeyLength keyLength = (CryptoOptions.KeyLength) keyLengthSpinner.getSelectedItem();
            Integer blockSize = (blockSpinner.getVisibility() == View.VISIBLE) ? (Integer) blockSpinner.getSelectedItem() : 0;
            CryptoOptions.CipherMode mode = (CryptoOptions.CipherMode) modeSpinner.getSelectedItem();
            CryptoOptions.Padding padding = paddingSpinner.isEnabled() ? (CryptoOptions.Padding) paddingSpinner.getSelectedItem() : CryptoOptions.Padding.NoPadding;
            CryptoOptions.Kdf kdf = (CryptoOptions.Kdf) kdfSpinner.getSelectedItem();

            if (protocol == null || keyLength == null || mode == null || kdf == null) {
                onError("A required dropdown option is not selected.", null);
                return;
            }
            
            CryptoOptions options = new CryptoOptions(protocol, keyLength, blockSize, mode, padding, kdf);
            int threads = threadCountSlider.getProgress() + 1;
            int chunkSize = CHUNK_SIZES_KB[chunkSizeSlider.getProgress()] * 1024;

            sourcePathForTempFile = getPathFromUri(selectedFileUri);
            if (sourcePathForTempFile == null) return;

            String destPath = getCacheDir().getAbsolutePath() + "/" + getFileName(selectedFileUri) + ".enc";

            resetUiState();
            setUiEnabled(false);
            onLog("Starting encryption...");
            onLog("Options: " + options.toString());

            executor.submit(() -> {
                try {
                    cryptoManager.encrypt(sourcePathForTempFile, destPath, password, options, chunkSize, threads, this);
                } catch (Exception e) {
                    onError("Encryption failed", e);
                }
            });

        } catch (Exception e) {
            onError("Invalid options selected or failed to start", e);
        }
    }

    @Override
    public void onSuccess(String message, String outputPath) {
        runOnUiThread(() -> {
            onLog("[SUCCESS] " + message);
            onLog("Overwriting original file...");
            try {
                overwriteOriginalFile(outputPath);
                onLog("File overwritten successfully.");
                Toast.makeText(this, "Encryption Successful!", Toast.LENGTH_SHORT).show();
                statusTextView.setText("✓ SUCCESS");
            } catch (Exception e) {
                onError("Failed to overwrite original file", e);
            } finally {
                cleanupTempFiles(outputPath);
                setUiEnabled(true);
                statusTextView.setVisibility(View.VISIBLE);
            }
        });
    }

    private void overwriteOriginalFile(String resultPath) throws Exception {
        if (selectedFileUri == null) {
            throw new IllegalStateException("Original file URI is missing.");
        }
        ContentResolver resolver = getContentResolver();
        try (InputStream in = new FileInputStream(resultPath);
             OutputStream out = resolver.openOutputStream(selectedFileUri, "wt")) { // 'wt' for write and truncate
            if (out == null) {
                throw new IOException("Failed to open output stream for URI: " + selectedFileUri.toString());
            }
            byte[] buffer = new byte[8192];
            int len;
            while ((len = in.read(buffer)) != -1) {
                out.write(buffer, 0, len);
            }
        }
    }

    private void cleanupTempFiles(String encryptedFilePath) {
        if (sourcePathForTempFile != null) {
            new File(sourcePathForTempFile).delete();
            sourcePathForTempFile = null;
        }
        if (encryptedFilePath != null) {
            new File(encryptedFilePath).delete();
        }
    }

    private void setUiEnabled(boolean enabled) {
        runOnUiThread(() -> {
            protocolSpinner.setEnabled(enabled);
            keyLengthSpinner.setEnabled(enabled);
            blockSpinner.setEnabled(enabled);
            modeSpinner.setEnabled(enabled);
            paddingSpinner.setEnabled(enabled);
            kdfSpinner.setEnabled(enabled);
            threadCountSlider.setEnabled(enabled);
            chunkSizeSlider.setEnabled(enabled);
            passwordInput.setEnabled(enabled);
            fileSelectButton.setEnabled(enabled);
            encryptButton.setEnabled(enabled);
            progressBar.setVisibility(enabled ? View.GONE : View.VISIBLE);
            if(enabled) progressBar.setProgress(0);
        });
    }
    
    private void resetUiState() {
        runOnUiThread(() -> {
            consoleTextView.setText("");
            statusTextView.setVisibility(View.GONE);
        });
    }

    private String getPathFromUri(Uri uri) {
        try {
            String tempFileName = "temp_adv_enc_" + System.currentTimeMillis();
            File tempFile = File.createTempFile(tempFileName, ".tmp", getCacheDir());
            try (InputStream in = getContentResolver().openInputStream(uri);
                 FileOutputStream out = new FileOutputStream(tempFile)) {
                byte[] buffer = new byte[8192];
                int len;
                while ((len = in.read(buffer)) != -1) {
                    out.write(buffer, 0, len);
                }
            }
            return tempFile.getAbsolutePath();
        } catch (Exception e) {
            onError("Failed to create a temporary file from URI", e);
            return null;
        }
    }

    private String getFileName(Uri uri) {
        String result = null;
        if (uri.getScheme().equals("content")) {
            try (Cursor cursor = getContentResolver().query(uri, null, null, null, null)) {
                if (cursor != null && cursor.moveToFirst()) {
                    int nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    if(nameIndex != -1){
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

    // CryptoListener Implementation

    @Override
    public void onStart(long totalBytes) {
        runOnUiThread(() -> {
            progressBar.setMax((int) totalBytes);
            progressBar.setProgress(0);
            onLog("Processing " + totalBytes + " bytes...");
        });
    }

    @Override
    public void onProgress(long currentBytes, long totalBytes) {
        runOnUiThread(() -> progressBar.setProgress((int) currentBytes));
    }

    @Override
    public void onError(String message, Exception e) {
        runOnUiThread(() -> {
            setUiEnabled(true);
            statusTextView.setText("✗ ERROR");
            statusTextView.setVisibility(View.VISIBLE);
            String logMsg = "[ERROR] " + message + (e != null ? ": " + e.getMessage() : "");
            onLog(logMsg);
             if (e != null) {
                e.printStackTrace();
            }
            Toast.makeText(AdvancedEncryptionActivity.this, "An Error Occurred", Toast.LENGTH_SHORT).show();
            cleanupTempFiles(null); // Clean up temp files on error
        });
    }

    public void onLog(String message) {
        runOnUiThread(() -> {
            consoleTextView.append(message + "\n");
            consoleScrollView.post(() -> consoleScrollView.fullScroll(View.FOCUS_DOWN));
        });
    }
}
