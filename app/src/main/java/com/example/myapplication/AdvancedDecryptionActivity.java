package com.example.myapplication;

import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
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
import com.example.myapplication.crypto.FileHeader;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

public class AdvancedDecryptionActivity extends AppCompatActivity implements CryptoListener {

    // UI Components
    private EditText passwordInput;
    private Button fileSelectButton, decryptButton;
    private TextView selectedFileTextView, consoleTextView, statusTextView;
    private ProgressBar progressBar;
    private ScrollView consoleScrollView;
    private CheckBox manualModeCheckbox;
    private LinearLayout headerInfoLayout, manualOptionsLayout;
    
    // Header Info UI
    private TextView infoProtocol, infoKeyLength, infoBlockSize, infoMode, infoPadding, infoKdf;

    // Manual Options UI
    private Spinner protocolSpinner, keyLengthSpinner, blockSpinner, modeSpinner, paddingSpinner, kdfSpinner;
    private TextView blockSpinnerLabel;
    
    // Performance UI
    private SeekBar threadCountSlider, chunkSizeSlider;
    private TextView threadCountValueTextView, chunkSizeValueTextView;

    // Member Variables
    private Uri selectedFileUri;
    private String tempSourcePath;
    private final CryptoManager cryptoManager = new CryptoManager();
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private ActivityResultLauncher<Intent> filePickerLauncher;
    private static final int[] CHUNK_SIZES_KB = {4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384};


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_advanced_decryption);
        setTitle("Advanced Decryption");

        initializeViews();
        setupFilePicker();
        setupManualSpinners();
        setupEventListeners();
        updateUiForManualMode(false);
    }

    private void initializeViews() {
        passwordInput = findViewById(R.id.password_input);
        fileSelectButton = findViewById(R.id.file_select_button);
        decryptButton = findViewById(R.id.decrypt_button);
        selectedFileTextView = findViewById(R.id.selected_file_textview);
        progressBar = findViewById(R.id.progress_bar);
        consoleTextView = findViewById(R.id.console_textview);
        consoleScrollView = findViewById(R.id.console_scrollview);
        statusTextView = findViewById(R.id.status_textview);
        manualModeCheckbox = findViewById(R.id.manual_mode_checkbox);
        headerInfoLayout = findViewById(R.id.header_info_layout);
        manualOptionsLayout = findViewById(R.id.manual_options_layout);

        infoProtocol = findViewById(R.id.info_protocol);
        infoKeyLength = findViewById(R.id.info_key_length);
        infoBlockSize = findViewById(R.id.info_block_size);
        infoMode = findViewById(R.id.info_mode);
        infoPadding = findViewById(R.id.info_padding);
        infoKdf = findViewById(R.id.info_kdf);

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
    }

    private void setupFilePicker() {
        filePickerLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            result -> {
                if (result.getResultCode() == RESULT_OK && result.getData() != null) {
                    selectedFileUri = result.getData().getData();
                    String fileName = getFileName(selectedFileUri);
                    selectedFileTextView.setText(fileName != null ? fileName : "No file selected");
                    prepareFileForDecryption();
                }
            });
    }

    private void setupManualSpinners() {
        ArrayAdapter<CryptoOptions.CryptoProtocol> protocolAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, CryptoOptions.CryptoProtocol.values());
        protocolAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        protocolSpinner.setAdapter(protocolAdapter);

        ArrayAdapter<CryptoOptions.Kdf> kdfAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, CryptoOptions.Kdf.values());
        kdfAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        kdfSpinner.setAdapter(kdfAdapter);
    }

    private void setupEventListeners() {
        fileSelectButton.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            intent.setType("*/*");
            filePickerLauncher.launch(intent);
        });

        decryptButton.setOnClickListener(v -> handleDecryption());

        manualModeCheckbox.setOnCheckedChangeListener((buttonView, isChecked) -> updateUiForManualMode(isChecked));

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

    private void updateUiForManualMode(boolean isManual) {
        headerInfoLayout.setVisibility(isManual ? View.GONE : View.VISIBLE);
        manualOptionsLayout.setVisibility(isManual ? View.VISIBLE : View.GONE);
        if (isManual) {
            updateDependantSpinners();
        }
    }

    private void prepareFileForDecryption() {
        if (selectedFileUri == null) return;
        resetUiState();
        
        // Asynchronously copy file and read header
        new Thread(() -> {
            tempSourcePath = getPathFromUri(selectedFileUri); // This copies the file to a temporary location
            if (tempSourcePath != null) {
                try (InputStream fis = new FileInputStream(tempSourcePath)) {
                    FileHeader header = FileHeader.fromStream(fis);
                    runOnUiThread(() -> displayHeaderInfo(header.getOptions()));
                } catch (Exception e) {
                    runOnUiThread(() -> {
                        headerInfoLayout.setVisibility(View.GONE);
                        onLog("Could not read file header. It might be corrupted or not an encrypted file from this app. Try manual mode.");
                    });
                }
            }
        }).start();
    }
    
    private void displayHeaderInfo(CryptoOptions options) {
        headerInfoLayout.setVisibility(View.VISIBLE);
        infoProtocol.setText("Protocol: " + options.getProtocol());
        infoKeyLength.setText("Key Length: " + options.getKeyLength().getBits() + "-bit");
        infoBlockSize.setText("Block Size: " + options.getBlockSizeBits() + "-bit");
        infoMode.setText("Mode: " + options.getMode());
        infoPadding.setText("Padding: " + options.getPadding());
        infoKdf.setText("KDF: " + options.getKdf());
    }

    private void handleDecryption() {
        if (tempSourcePath == null) {
            onError("Please select a file first.", null);
            return;
        }
        char[] password = passwordInput.getText().toString().toCharArray();
        if (password.length == 0) {
            onError("Password cannot be empty.", null);
            return;
        }

        try {
            CryptoOptions manualOptions = null;
            if (manualModeCheckbox.isChecked()) {
                CryptoOptions.CryptoProtocol protocol = (CryptoOptions.CryptoProtocol) protocolSpinner.getSelectedItem();
                CryptoOptions.KeyLength keyLength = (CryptoOptions.KeyLength) keyLengthSpinner.getSelectedItem();
                Integer blockSize = (blockSpinner.getVisibility() == View.VISIBLE) ? (Integer) blockSpinner.getSelectedItem() : 0;
                CryptoOptions.CipherMode mode = (CryptoOptions.CipherMode) modeSpinner.getSelectedItem();
                CryptoOptions.Padding padding = paddingSpinner.isEnabled() ? (CryptoOptions.Padding) paddingSpinner.getSelectedItem() : CryptoOptions.Padding.NoPadding;
                CryptoOptions.Kdf kdf = (CryptoOptions.Kdf) kdfSpinner.getSelectedItem();
                
                if (protocol == null || keyLength == null || mode == null || kdf == null) {
                    onError("A required dropdown option is not selected for manual mode.", null);
                    return;
                }
                manualOptions = new CryptoOptions(protocol, keyLength, blockSize, mode, padding, kdf);
                onLog("Starting decryption in MANUAL mode...");
                onLog("Manual Options: " + manualOptions.toString());
            } else {
                 onLog("Starting decryption in AUTOMATIC mode...");
            }

            int threads = threadCountSlider.getProgress() + 1;
            int chunkSize = CHUNK_SIZES_KB[chunkSizeSlider.getProgress()] * 1024;

            String originalFileName = getFileName(selectedFileUri).replaceAll("\\.enc$|\\.tmp$", "");
            File destFile = new File(getExternalCacheDir(), "dec_" + originalFileName);
            String destPath = destFile.getAbsolutePath();

            resetUiState();
            setUiEnabled(false);
            
            final CryptoOptions finalManualOptions = manualOptions;
            executor.submit(() -> {
                try {
                    cryptoManager.decrypt(tempSourcePath, destPath, password, finalManualOptions, chunkSize, threads, this);
                } catch (Exception e) {
                    onError("Decryption failed", e);
                }
            });

        } catch (Exception e) {
            onError("Failed to start decryption", e);
        }
    }
    
    // Spinner update logic (similar to AdvancedEncryptionActivity)
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

        updateModeSpinner();
    }

    private void updateModeSpinner() {
        CryptoOptions.CryptoProtocol selectedProtocol = (CryptoOptions.CryptoProtocol) protocolSpinner.getSelectedItem();
        if (selectedProtocol == null) return;
        
        List<CryptoOptions.CipherMode> modes = selectedProtocol.getSupportedModes().stream()
                .filter(m -> selectedProtocol.isModeSupported(m))
                .collect(Collectors.toList());

        ArrayAdapter<CryptoOptions.CipherMode> modeAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, modes);
        modeAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        modeSpinner.setAdapter(modeAdapter);
        updatePaddingSpinner();
    }

    private void updatePaddingSpinner() {
        Object selectedItem = modeSpinner.getSelectedItem();
        if (selectedItem == null) {
            paddingSpinner.setEnabled(false);
            return;
        }

        CryptoOptions.CipherMode selectedMode = (CryptoOptions.CipherMode) selectedItem;
        paddingSpinner.setEnabled(!selectedMode.isStreamMode());
        if (!selectedMode.isStreamMode()){
             ArrayAdapter<CryptoOptions.Padding> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, CryptoOptions.Padding.values());
            adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
            paddingSpinner.setAdapter(adapter);
        } else {
            ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, new String[]{"NoPadding"});
            paddingSpinner.setAdapter(adapter);
        }
    }
    
    // Other helper methods
    private void setUiEnabled(boolean enabled) {
        runOnUiThread(() -> {
            passwordInput.setEnabled(enabled);
            fileSelectButton.setEnabled(enabled);
            decryptButton.setEnabled(enabled);
            manualModeCheckbox.setEnabled(enabled);
            threadCountSlider.setEnabled(enabled);
            chunkSizeSlider.setEnabled(enabled);
            // Also disable/enable manual spinners if manual mode is active
            if(manualModeCheckbox.isChecked()) {
                protocolSpinner.setEnabled(enabled);
                keyLengthSpinner.setEnabled(enabled);
                blockSpinner.setEnabled(enabled);
                modeSpinner.setEnabled(enabled);
                paddingSpinner.setEnabled(enabled);
                kdfSpinner.setEnabled(enabled);
            }
            progressBar.setVisibility(enabled ? View.GONE : View.VISIBLE);
        });
    }
    
    private void resetUiState() {
        runOnUiThread(() -> {
            consoleTextView.setText("");
            statusTextView.setVisibility(View.GONE);
            progressBar.setProgress(0);
        });
    }

    private String getPathFromUri(Uri uri) {
        try {
            File tempFile = File.createTempFile("temp_adv_dec", ".tmp", getCacheDir());
            tempFile.deleteOnExit();
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
        String result = "file.tmp";
        if (uri.getScheme().equals("content")) {
            try (Cursor cursor = getContentResolver().query(uri, null, null, null, null)) {
                if (cursor != null && cursor.moveToFirst()) {
                    int nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    if(nameIndex != -1) result = cursor.getString(nameIndex);
                }
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
    public void onSuccess(String message) {
        runOnUiThread(() -> {
            setUiEnabled(true);
            statusTextView.setText("✓ SUCCESS");
            statusTextView.setVisibility(View.VISIBLE);
            onLog("[SUCCESS] " + message);
            Toast.makeText(this, "Decryption Successful!", Toast.LENGTH_SHORT).show();
        });
    }

    @Override
    public void onError(String message, Exception e) {
        runOnUiThread(() -> {
            setUiEnabled(true);
            statusTextView.setText("✗ ERROR");
            statusTextView.setVisibility(View.VISIBLE);
            String logMsg = "[ERROR] " + message + (e != null ? ": " + e.getMessage() : "");
            onLog(logMsg);
            if (e != null) e.printStackTrace();
            Toast.makeText(this, "An Error Occurred", Toast.LENGTH_SHORT).show();
        });
    }

    @Override
    public void onLog(String message) {
        runOnUiThread(() -> {
            consoleTextView.append(message + "\n");
            consoleScrollView.post(() -> consoleScrollView.fullScroll(View.FOCUS_DOWN));
        });
    }
}
