package com.example.myapplication;

import android.content.ContentResolver;
import android.content.Intent;
import android.database.Cursor;
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

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

public class AdvancedEncryptionActivity extends AppCompatActivity implements CryptoListener {

    private Spinner protocolSpinner, keyLengthSpinner, blockSpinner, modeSpinner, paddingSpinner, kdfSpinner;
    private SeekBar threadCountSlider;
    private TextView threadCountValueTextView;
    private EditText passwordInput;
    private Button fileSelectButton, encryptButton;
    private TextView selectedFileTextView, consoleTextView;
    private ProgressBar progressBar;
    private ScrollView consoleScrollView;

    private Uri selectedFileUri;
    private final CryptoManager cryptoManager = new CryptoManager();
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private ActivityResultLauncher<Intent> filePickerLauncher;

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

    private void initializeViews() {
        protocolSpinner = findViewById(R.id.protocol_spinner);
        keyLengthSpinner = findViewById(R.id.key_length_spinner);
        blockSpinner = findViewById(R.id.block_size_spinner);
        modeSpinner = findViewById(R.id.mode_spinner);
        paddingSpinner = findViewById(R.id.padding_spinner);
        kdfSpinner = findViewById(R.id.kdf_spinner);
        threadCountSlider = findViewById(R.id.thread_count_slider);
        threadCountValueTextView = findViewById(R.id.thread_count_value_textview);
        passwordInput = findViewById(R.id.password_input);
        fileSelectButton = findViewById(R.id.file_select_button);
        encryptButton = findViewById(R.id.encrypt_button);
        selectedFileTextView = findViewById(R.id.selected_file_textview);
        progressBar = findViewById(R.id.progress_bar);
        consoleTextView = findViewById(R.id.console_textview);
        consoleScrollView = findViewById(R.id.console_scrollview);
    }

    private void setupFilePicker() {
        filePickerLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == RESULT_OK && result.getData() != null) {
                        selectedFileUri = result.getData().getData();
                        selectedFileTextView.setText(getFileName(selectedFileUri));
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

        updateBlockAndKeyLengthSpinners();
    }

    private void setupEventListeners() {
        protocolSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                updateBlockAndKeyLengthSpinners();
            }
            @Override
            public void onNothingSelected(AdapterView<?> parent) {}
        });

        blockSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                updateModeSpinner();
            }
            @Override
            public void onNothingSelected(AdapterView<?> parent) {}
        });

        modeSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                updatePaddingSpinner();
            }
            @Override
            public void onNothingSelected(AdapterView<?> parent) {}
        });

        fileSelectButton.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            intent.setType("*/*");
            filePickerLauncher.launch(intent);
        });

        encryptButton.setOnClickListener(v -> handleEncryption());

        int maxThreads = Math.max(1, Runtime.getRuntime().availableProcessors() * 2 - 2);
        threadCountSlider.setMax(maxThreads - 1);
        threadCountSlider.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
            @Override
            public void onProgressChanged(SeekBar seekBar, int progress, boolean fromUser) {
                threadCountValueTextView.setText(String.valueOf(progress + 1));
            }
            @Override public void onStartTrackingTouch(SeekBar seekBar) {} 
            @Override public void onStopTrackingTouch(SeekBar seekBar) {}
        });
        threadCountValueTextView.setText("1");
    }

    private void updateBlockAndKeyLengthSpinners() {
        CryptoOptions.CryptoProtocol selectedProtocol = (CryptoOptions.CryptoProtocol) protocolSpinner.getSelectedItem();
        if (selectedProtocol == null) return;

        ArrayAdapter<Integer> blockAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, selectedProtocol.getSupportedBlockBits());
        blockAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        blockSpinner.setAdapter(blockAdapter);

        ArrayAdapter<CryptoOptions.KeyLength> keyLengthAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, selectedProtocol.getSupportedKeyLengths());
        keyLengthAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        keyLengthSpinner.setAdapter(keyLengthAdapter);
    }

    private void updateModeSpinner() {
        CryptoOptions.CryptoProtocol selectedProtocol = (CryptoOptions.CryptoProtocol) protocolSpinner.getSelectedItem();
        if (selectedProtocol == null) return;

        Integer selectedBlockSize = (Integer) blockSpinner.getSelectedItem();
        if (selectedBlockSize == null) return;

        List<CryptoOptions.CipherMode> allModes = selectedProtocol.getSupportedModes();
        List<CryptoOptions.CipherMode> supportedModes = allModes.stream()
                .filter(mode -> {
                    if (mode == CryptoOptions.CipherMode.XTS) {
                        return selectedBlockSize == 128;
                    }
                    return true;
                })
                .collect(Collectors.toList());

        ArrayAdapter<CryptoOptions.CipherMode> modeAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, supportedModes);
        modeAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        modeSpinner.setAdapter(modeAdapter);
    }

    private void updatePaddingSpinner() {
        Object selectedItem = modeSpinner.getSelectedItem();
        if (selectedItem == null) {
            paddingSpinner.setAdapter(null);
            paddingSpinner.setEnabled(false);
            return;
        }

        CryptoOptions.CipherMode selectedMode = (CryptoOptions.CipherMode) selectedItem;
        boolean isStreamCipher = selectedMode == CryptoOptions.CipherMode.CTR || selectedMode == CryptoOptions.CipherMode.GCM || selectedMode == CryptoOptions.CipherMode.CCM || selectedMode == CryptoOptions.CipherMode.OFB || selectedMode == CryptoOptions.CipherMode.CFB || selectedMode == CryptoOptions.CipherMode.OCB;

        if (isStreamCipher) {
            ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, new String[]{"NoPadding"});
            paddingSpinner.setAdapter(adapter);
            paddingSpinner.setEnabled(false);
        } else {
            ArrayAdapter<CryptoOptions.Padding> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, CryptoOptions.Padding.values());
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
            Integer blockSize = (Integer) blockSpinner.getSelectedItem();
            CryptoOptions.CipherMode mode = (CryptoOptions.CipherMode) modeSpinner.getSelectedItem();
            CryptoOptions.Padding padding = paddingSpinner.isEnabled() ? (CryptoOptions.Padding) paddingSpinner.getSelectedItem() : CryptoOptions.Padding.NoPadding;
            CryptoOptions.Kdf kdf = (CryptoOptions.Kdf) kdfSpinner.getSelectedItem();

            if (mode == null) {
                 onError("No valid mode available for this protocol/block size combination.", null);
                 return;
            }

            CryptoOptions options = new CryptoOptions(protocol, keyLength, blockSize, mode, padding, kdf);
            int threads = threadCountSlider.getProgress() + 1;
            int chunkSize = 1024 * 1024; // 1 MB chunk size

            String sourcePath = getPathFromUri(selectedFileUri);
            if (sourcePath == null) {
                onError("Could not get the real path for the selected file. This can happen with cloud-based files (Google Drive, Dropbox). Please select a file stored locally on your device.", null);
                return;
            }
            String destPath = sourcePath + ".enc";

            setUiEnabled(false);
            onLog("Starting encryption...");
            onLog("Options: " + options.toString());

            executor.submit(() -> {
                try {
                    cryptoManager.encrypt(sourcePath, destPath, password, options, chunkSize, threads, this);
                } catch (Exception e) {
                    onError("Encryption failed", e);
                }
            });

        } catch (Exception e) {
            onError("Invalid options selected", e);
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
            passwordInput.setEnabled(enabled);
            fileSelectButton.setEnabled(enabled);
            encryptButton.setEnabled(enabled);
            progressBar.setVisibility(enabled ? View.INVISIBLE : View.VISIBLE);
        });
    }

    private String getPathFromUri(Uri uri) {
        File tempFile = null;
        try {
            ContentResolver resolver = getContentResolver();
            String fileName = getFileName(uri);
            tempFile = File.createTempFile("upload_temp", fileName, getCacheDir());
            tempFile.deleteOnExit();
            try (InputStream in = resolver.openInputStream(uri);
                 FileOutputStream out = new FileOutputStream(tempFile)) {
                byte[] buffer = new byte[8192];
                int len;
                while ((len = in.read(buffer)) != -1) {
                    out.write(buffer, 0, len);
                }
            }
            return tempFile.getAbsolutePath();
        } catch (Exception e) {
            if (tempFile != null) {
                tempFile.delete();
            }
            onError("Failed to process file URI", e);
            return null;
        }
    }

    private String getFileName(Uri uri) {
        String result = "tempfile";
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
            if (result != null) {
                 int cut = result.lastIndexOf('/');
                 if (cut != -1) {
                    result = result.substring(cut + 1);
                 }
            }
        }
        return result;
    }

    @Override
    public void onStart(long totalBytes) {
        runOnUiThread(() -> {
            progressBar.setProgress(0);
            progressBar.setMax(100);
            onLog("Processing " + totalBytes + " bytes...");
        });
    }

    @Override
    public void onProgress(long current, long total) {
        int progress = (int) ((current * 100) / total);
        runOnUiThread(() -> progressBar.setProgress(progress));
    }

    @Override
    public void onSuccess(String message) {
        runOnUiThread(() -> {
            setUiEnabled(true);
            onLog("[SUCCESS] " + message);
            Toast.makeText(this, "Encryption Successful!", Toast.LENGTH_SHORT).show();
        });
    }

    @Override
    public void onError(String message, Exception e) {
        runOnUiThread(() -> {
            setUiEnabled(true);
            String exceptionMessage = e != null ? e.getClass().getSimpleName() + ": " + e.getMessage() : "";
            String logMsg = "[ERROR] " + message + "\n" + exceptionMessage;
            onLog(logMsg);
            Toast.makeText(this, "An Error Occurred", Toast.LENGTH_SHORT).show();
        });
    }

    private void onLog(String message) {
        runOnUiThread(() -> {
            consoleTextView.append(message + "\n");
            consoleScrollView.post(() -> consoleScrollView.fullScroll(View.FOCUS_DOWN));
        });
    }
}
