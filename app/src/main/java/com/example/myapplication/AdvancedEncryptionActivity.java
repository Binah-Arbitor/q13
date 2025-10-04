package com.example.myapplication;

import android.content.ContentResolver;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.SeekBar;
import android.widget.Spinner;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import com.example.myapplication.crypto.CryptoListener;
import com.example.myapplication.crypto.CryptoManager;
import com.example.myapplication.crypto.CryptoOptions;
import com.google.android.material.bottomnavigation.BottomNavigationView;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.UUID;

public class AdvancedEncryptionActivity extends AppCompatActivity implements CryptoListener {

    private static final int FILE_SELECT_CODE = 0;
    private Uri selectedFileUri;

    private Spinner protocolSpinner, keyLengthSpinner, blockSizeSpinner, modeSpinner, paddingSpinner, kdfSpinner, tagLengthSpinner;
    private TextView selectedFileTextView, statusTextView, consoleTextView, chunkSizeTextView, threadCountTextView;
    private ProgressBar progressBar;
    private Button fileSelectButton, encryptButton;
    private EditText passwordInput;
    private SeekBar chunkSizeSlider, threadCountSlider;
    private LinearLayout tagLengthLayout;
    private BottomNavigationView bottomNav;

    private CryptoManager cryptoManager;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_advanced_encryption);

        cryptoManager = new CryptoManager();

        // Initialize UI components
        protocolSpinner = findViewById(R.id.protocol_spinner);
        keyLengthSpinner = findViewById(R.id.key_length_spinner);
        blockSizeSpinner = findViewById(R.id.block_size_spinner);
        modeSpinner = findViewById(R.id.mode_spinner);
        paddingSpinner = findViewById(R.id.padding_spinner);
        kdfSpinner = findViewById(R.id.kdf_spinner);
        tagLengthSpinner = findViewById(R.id.tag_length_spinner);
        tagLengthLayout = findViewById(R.id.tag_length_layout);

        selectedFileTextView = findViewById(R.id.selected_file_textview);
        statusTextView = findViewById(R.id.status_textview);
        consoleTextView = findViewById(R.id.console_textview);
        chunkSizeTextView = findViewById(R.id.chunk_size_value_textview);
        threadCountTextView = findViewById(R.id.thread_count_value_textview);

        progressBar = findViewById(R.id.progress_bar);
        fileSelectButton = findViewById(R.id.file_select_button);
        encryptButton = findViewById(R.id.encrypt_button);
        passwordInput = findViewById(R.id.password_input);
        chunkSizeSlider = findViewById(R.id.chunk_size_slider);
        threadCountSlider = findViewById(R.id.thread_count_slider);
        bottomNav = findViewById(R.id.bottom_navigation);

        setupSpinners();
        setupSliders();
        setupButtonListeners();
        setupBottomNavigation();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main_menu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == R.id.action_switch_to_simple) {
            startActivity(new Intent(this, MainActivity.class));
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void setupBottomNavigation() {
        bottomNav.setSelectedItemId(R.id.nav_encrypt);
        bottomNav.setOnItemSelectedListener(item -> {
            if (item.getItemId() == R.id.nav_decrypt) {
                startActivity(new Intent(this, AdvancedDecryptionActivity.class));
                finish(); // Finish current activity to prevent stack buildup
                return true;
            }
            return false;
        });
    }

    private void setUiEnabled(boolean enabled) {
        protocolSpinner.setEnabled(enabled);
        keyLengthSpinner.setEnabled(enabled);
        blockSizeSpinner.setEnabled(enabled);
        modeSpinner.setEnabled(enabled);
        paddingSpinner.setEnabled(enabled);
        kdfSpinner.setEnabled(enabled);
        tagLengthSpinner.setEnabled(enabled);
        fileSelectButton.setEnabled(enabled);
        encryptButton.setEnabled(enabled);
        passwordInput.setEnabled(enabled);
        chunkSizeSlider.setEnabled(enabled);
        threadCountSlider.setEnabled(enabled);
        bottomNav.setEnabled(enabled);
    }

    private void setupSpinners() {
        // Protocol Spinner
        protocolSpinner.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, CryptoOptions.CryptoProtocol.values()));
        protocolSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                updateDependentSpinners();
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {}
        });

        // Mode Spinner
        modeSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                updatePaddingAndTagSpinners();
            }
            @Override
            public void onNothingSelected(AdapterView<?> parent) {}
        });
        
        // Tag Length Spinner
        tagLengthSpinner.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, CryptoOptions.TagLength.values()));

        // KDF Spinner
        kdfSpinner.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, CryptoOptions.Kdf.values()));

        // Set default selections
        protocolSpinner.setSelection(Arrays.asList(CryptoOptions.CryptoProtocol.values()).indexOf(CryptoOptions.getDefault().getProtocol()));
        kdfSpinner.setSelection(Arrays.asList(CryptoOptions.Kdf.values()).indexOf(CryptoOptions.getDefault().getKdf()));
        updateDependentSpinners(); // Initial population
    }

    private void updateDependentSpinners() {
        CryptoOptions.CryptoProtocol selectedProtocol = (CryptoOptions.CryptoProtocol) protocolSpinner.getSelectedItem();

        // Update Key Length Spinner
        keyLengthSpinner.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, selectedProtocol.getSupportedKeyLengths()));

        // Update Block Size Spinner
        blockSizeSpinner.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, selectedProtocol.getSupportedBlockSizes()));

        // Update Mode Spinner
        modeSpinner.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, selectedProtocol.getSupportedModes()));

        // Restore defaults if possible
        if (selectedProtocol.getSupportedKeyLengths().contains(CryptoOptions.getDefault().getKeyLength())) {
            keyLengthSpinner.setSelection(selectedProtocol.getSupportedKeyLengths().indexOf(CryptoOptions.getDefault().getKeyLength()));
        }
        if (selectedProtocol.getSupportedBlockSizes().contains(CryptoOptions.getDefault().getBlockSize())) {
            blockSizeSpinner.setSelection(selectedProtocol.getSupportedBlockSizes().indexOf(CryptoOptions.getDefault().getBlockSize()));
        }
        if (selectedProtocol.getSupportedModes().contains(CryptoOptions.getDefault().getMode())) {
            modeSpinner.setSelection(selectedProtocol.getSupportedModes().indexOf(CryptoOptions.getDefault().getMode()));
        }
        
        updatePaddingAndTagSpinners();
    }

    private void updatePaddingAndTagSpinners() {
        CryptoOptions.CipherMode selectedMode = (CryptoOptions.CipherMode) modeSpinner.getSelectedItem();
        
        // Show/hide tag length based on whether the mode is AEAD
        tagLengthLayout.setVisibility(selectedMode.isAeadMode() ? View.VISIBLE : View.GONE);

        // Disable padding for stream modes
        if (selectedMode.isStreamMode()) {
            paddingSpinner.setEnabled(false);
            paddingSpinner.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, new CryptoOptions.Padding[]{CryptoOptions.Padding.NoPadding}));
        } else {
            paddingSpinner.setEnabled(true);
            paddingSpinner.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, CryptoOptions.Padding.values()));
            if (Arrays.asList(CryptoOptions.Padding.values()).contains(CryptoOptions.getDefault().getPadding())) {
                paddingSpinner.setSelection(Arrays.asList(CryptoOptions.Padding.values()).indexOf(CryptoOptions.getDefault().getPadding()));
            }
        }
    }

    private void setupSliders() {
        // Chunk Size Slider
        chunkSizeSlider.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
            @Override
            public void onProgressChanged(SeekBar seekBar, int progress, boolean fromUser) {
                chunkSizeTextView.setText(getChunkSizeLabel(progress));
            }
            @Override
            public void onStartTrackingTouch(SeekBar seekBar) {}
            @Override
            public void onStopTrackingTouch(SeekBar seekBar) {}
        });
        chunkSizeTextView.setText(getChunkSizeLabel(chunkSizeSlider.getProgress()));

        // Thread Count Slider
        threadCountSlider.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
            @Override
            public void onProgressChanged(SeekBar seekBar, int progress, boolean fromUser) {
                threadCountTextView.setText(String.valueOf(progress + 1));
            }
            @Override
            public void onStartTrackingTouch(SeekBar seekBar) {}
            @Override
            public void onStopTrackingTouch(SeekBar seekBar) {}
        });
        threadCountTextView.setText(String.valueOf(threadCountSlider.getProgress() + 1));
    }

    private void setupButtonListeners() {
        fileSelectButton.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
            intent.setType("*/*");
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            startActivityForResult(Intent.createChooser(intent, "Select a file to encrypt"), FILE_SELECT_CODE);
        });

        encryptButton.setOnClickListener(v -> {
            if (selectedFileUri == null) {
                logToConsole("Please select a file first.");
                return;
            }
            if (passwordInput.getText().length() == 0) {
                logToConsole("Please enter a password.");
                return;
            }

            try {
                String inputPath = copyUriToCache(selectedFileUri);
                if (inputPath == null) {
                    onError("File processing failed.", new Exception("Could not copy file to cache."));
                    return;
                }
                
                String originalFileName = getFileName(selectedFileUri);
                String outputPath = getCacheDir().getAbsolutePath() + File.separator + originalFileName + ".enc";

                CryptoOptions options = new CryptoOptions(
                        (CryptoOptions.CryptoProtocol) protocolSpinner.getSelectedItem(),
                        (CryptoOptions.KeyLength) keyLengthSpinner.getSelectedItem(),
                        (CryptoOptions.BlockSize) blockSizeSpinner.getSelectedItem(),
                        (CryptoOptions.CipherMode) modeSpinner.getSelectedItem(),
                        (CryptoOptions.Padding) paddingSpinner.getSelectedItem(),
                        (CryptoOptions.TagLength) tagLengthSpinner.getSelectedItem(),
                        (CryptoOptions.Kdf) kdfSpinner.getSelectedItem()
                );

                int chunkSize = getChunkSizeInBytes(chunkSizeSlider.getProgress());
                int threadCount = threadCountSlider.getProgress() + 1;

                cryptoManager.encrypt(inputPath, outputPath, passwordInput.getText().toString().toCharArray(), options, chunkSize, threadCount, this);

            } catch (Exception e) {
                onError("Encryption setup failed.", e);
            }
        });
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == FILE_SELECT_CODE && resultCode == RESULT_OK) {
            selectedFileUri = data.getData();
            String fileName = getFileName(selectedFileUri);
            selectedFileTextView.setText("Selected: " + fileName);
            logToConsole("File URI: " + selectedFileUri.toString());
        }
    }

    @Override
    public void onStart(long totalSize) {
        runOnUiThread(() -> {
            setUiEnabled(false);
            consoleTextView.setText("");
            logToConsole("Starting encryption...");
            logToConsole("Total size: " + totalSize + " bytes");
            progressBar.setMax((int) totalSize);
            progressBar.setProgress(0);
            progressBar.setVisibility(View.VISIBLE);
            statusTextView.setVisibility(View.GONE);
        });
    }

    @Override
    public void onProgress(long bytesProcessed, long totalSize) {
        runOnUiThread(() -> {
            progressBar.setProgress((int) bytesProcessed);
        });
    }

    @Override
    public void onSuccess(String message, String outputPath) {
        runOnUiThread(() -> {
            setUiEnabled(true);
            progressBar.setVisibility(View.GONE);
            statusTextView.setText("✓ SUCCESS");
            statusTextView.setVisibility(View.VISIBLE);
            logToConsole(message);
            logToConsole("Output file saved in app cache: " + outputPath);
        });
    }

    @Override
    public void onError(String message, Exception e) {
        runOnUiThread(() -> {
            setUiEnabled(true);
            progressBar.setVisibility(View.GONE);
            statusTextView.setText("✗ ERROR");
            statusTextView.setVisibility(View.VISIBLE);
            logToConsole(message + "\n" + e.toString());
        });
    }
    
    @Override
    public void onLog(String message) {
        runOnUiThread(() -> logToConsole(message));
    }

    private void logToConsole(String message) {
        consoleTextView.append(message + "\n");
    }

    private String getFileName(Uri uri) {
        String result = null;
        if (uri.getScheme().equals("content")) {
            try (Cursor cursor = getContentResolver().query(uri, null, null, null, null)) {
                if (cursor != null && cursor.moveToFirst()) {
                    int index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    if(index > -1) {
                        result = cursor.getString(index);
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
        return result != null ? result : UUID.randomUUID().toString();
    }
    
    private String copyUriToCache(Uri uri) {
        if (uri == null) return null;
        ContentResolver contentResolver = getContentResolver();
        String fileName = getFileName(uri);
        File tempFile = new File(getCacheDir(), fileName);

        try (InputStream in = contentResolver.openInputStream(uri);
             OutputStream out = new FileOutputStream(tempFile)) {
            if (in == null) return null;
            byte[] buffer = new byte[8192];
            int len;
            while ((len = in.read(buffer)) != -1) {
                out.write(buffer, 0, len);
            }
            return tempFile.getAbsolutePath();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private int getChunkSizeInBytes(int progress) {
        return (int) (Math.pow(2, progress) * 4 * 1024);
    }

    private String getChunkSizeLabel(int progress) {
        int sizeInKb = (int) (Math.pow(2, progress) * 4);
        if (sizeInKb < 1024) {
            return sizeInKb + " KB";
        } else {
            return (sizeInKb / 1024) + " MB";
        }
    }
}
