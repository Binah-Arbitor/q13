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
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.SeekBar;
import android.widget.Spinner;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import com.example.myapplication.crypto.CryptoListener;
import com.example.myapplication.crypto.CryptoManager;
import com.example.myapplication.crypto.CryptoOptions;
import com.example.myapplication.crypto.FileHeader;
import com.google.android.material.bottomnavigation.BottomNavigationView;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.UUID;

public class AdvancedDecryptionActivity extends AppCompatActivity implements CryptoListener {

    private static final int FILE_SELECT_CODE = 1;
    private Uri selectedFileUri;

    private Spinner protocolSpinner, keyLengthSpinner, blockSizeSpinner, modeSpinner, paddingSpinner, kdfSpinner, tagLengthSpinner;
    private TextView selectedFileTextView, statusTextView, consoleTextView, chunkSizeTextView;
    private ProgressBar progressBar;
    private Button fileSelectButton, decryptButton;
    private EditText passwordInput;
    private CheckBox manualSettingsCheckbox;
    private SeekBar chunkSizeSlider;
    private BottomNavigationView bottomNav;

    private CryptoManager cryptoManager;
    private View manualSettingsLayout;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_advanced_decryption);

        cryptoManager = new CryptoManager();

        // Initialize UI components
        manualSettingsLayout = findViewById(R.id.manual_settings_layout);
        protocolSpinner = findViewById(R.id.protocol_spinner);
        keyLengthSpinner = findViewById(R.id.key_length_spinner);
        blockSizeSpinner = findViewById(R.id.block_size_spinner);
        modeSpinner = findViewById(R.id.mode_spinner);
        paddingSpinner = findViewById(R.id.padding_spinner);
        kdfSpinner = findViewById(R.id.kdf_spinner);
        tagLengthSpinner = findViewById(R.id.tag_length_spinner);

        selectedFileTextView = findViewById(R.id.selected_file_textview);
        statusTextView = findViewById(R.id.status_textview);
        consoleTextView = findViewById(R.id.console_textview);
        chunkSizeTextView = findViewById(R.id.chunk_size_value_textview);

        progressBar = findViewById(R.id.progress_bar);
        fileSelectButton = findViewById(R.id.file_select_button);
        decryptButton = findViewById(R.id.decrypt_button);
        passwordInput = findViewById(R.id.password_input);
        manualSettingsCheckbox = findViewById(R.id.manual_settings_checkbox);
        chunkSizeSlider = findViewById(R.id.chunk_size_slider);
        bottomNav = findViewById(R.id.bottom_navigation);

        setupSpinners();
        setupSliders();
        setupButtonListeners();
        setupCheckboxListener();
        setupBottomNavigation();

        manualSettingsLayout.setVisibility(View.GONE);
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
        bottomNav.setSelectedItemId(R.id.nav_decrypt);
        bottomNav.setOnItemSelectedListener(item -> {
            if (item.getItemId() == R.id.nav_encrypt) {
                startActivity(new Intent(this, AdvancedEncryptionActivity.class));
                finish(); // Finish current activity to prevent stack buildup
                return true;
            }
            return false;
        });
    }

    private void setUiEnabled(boolean enabled) {
        manualSettingsCheckbox.setEnabled(enabled);
        fileSelectButton.setEnabled(enabled);
        decryptButton.setEnabled(enabled);
        passwordInput.setEnabled(enabled);
        chunkSizeSlider.setEnabled(enabled);
        bottomNav.setEnabled(enabled);

        // Only enable manual spinners if the checkbox is checked
        boolean manualEnabled = enabled && manualSettingsCheckbox.isChecked();
        protocolSpinner.setEnabled(manualEnabled);
        keyLengthSpinner.setEnabled(manualEnabled);
        blockSizeSpinner.setEnabled(manualEnabled);
        modeSpinner.setEnabled(manualEnabled);
        paddingSpinner.setEnabled(manualEnabled);
        kdfSpinner.setEnabled(manualEnabled);
        tagLengthSpinner.setEnabled(manualEnabled);
    }

    private void setupSpinners() {
        protocolSpinner.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, CryptoOptions.CryptoProtocol.values()));
        protocolSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                updateDependentSpinners();
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {}
        });

        modeSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                updatePaddingAndTagSpinners();
            }
            @Override
            public void onNothingSelected(AdapterView<?> parent) {}
        });

        tagLengthSpinner.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, CryptoOptions.TagLength.values()));
        kdfSpinner.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, CryptoOptions.Kdf.values()));
    }

    private void updateDependentSpinners() {
        CryptoOptions.CryptoProtocol selectedProtocol = (CryptoOptions.CryptoProtocol) protocolSpinner.getSelectedItem();
        keyLengthSpinner.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, selectedProtocol.getSupportedKeyLengths()));
        blockSizeSpinner.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, selectedProtocol.getSupportedBlockSizes()));
        modeSpinner.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, selectedProtocol.getSupportedModes()));
    }

    private void updatePaddingAndTagSpinners() {
        CryptoOptions.CipherMode selectedMode = (CryptoOptions.CipherMode) modeSpinner.getSelectedItem();
        
        findViewById(R.id.tag_length_layout).setVisibility(selectedMode.isAeadMode() ? View.VISIBLE : View.GONE);

        if (selectedMode.isStreamMode()) {
            paddingSpinner.setEnabled(false);
            paddingSpinner.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, new CryptoOptions.Padding[]{CryptoOptions.Padding.NoPadding}));
        } else {
            paddingSpinner.setEnabled(true);
            paddingSpinner.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, CryptoOptions.Padding.values()));
        }
    }

    private void setupSliders() {
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
    }

    private void setupCheckboxListener() {
        manualSettingsCheckbox.setOnCheckedChangeListener((buttonView, isChecked) -> {
            manualSettingsLayout.setVisibility(isChecked ? View.VISIBLE : View.GONE);
             setUiEnabled(true); // Re-evaluate UI state
            if (!isChecked && selectedFileUri != null) {
                readHeaderAndAutoPopulate();
            }
        });
    }

    private void setupButtonListeners() {
        fileSelectButton.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
            intent.setType("*/*");
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            startActivityForResult(Intent.createChooser(intent, "Select a file to decrypt"), FILE_SELECT_CODE);
        });

        decryptButton.setOnClickListener(v -> {
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
                
                String originalFileName = getFileName(selectedFileUri).replace(".enc", ".dec");
                String outputPath = getCacheDir().getAbsolutePath() + File.separator + originalFileName;

                CryptoOptions manualOptions = null;
                if (manualSettingsCheckbox.isChecked()) {
                    manualOptions = new CryptoOptions(
                            (CryptoOptions.CryptoProtocol) protocolSpinner.getSelectedItem(),
                            (CryptoOptions.KeyLength) keyLengthSpinner.getSelectedItem(),
                            (CryptoOptions.BlockSize) blockSizeSpinner.getSelectedItem(),
                            (CryptoOptions.CipherMode) modeSpinner.getSelectedItem(),
                            (CryptoOptions.Padding) paddingSpinner.getSelectedItem(),
                            (CryptoOptions.TagLength) tagLengthSpinner.getSelectedItem(),
                            (CryptoOptions.Kdf) kdfSpinner.getSelectedItem()
                    );
                }

                int chunkSize = getChunkSizeInBytes(chunkSizeSlider.getProgress());

                cryptoManager.decrypt(inputPath, outputPath, passwordInput.getText().toString().toCharArray(), manualOptions, chunkSize, 1, this);

            } catch (Exception e) {
                onError("Decryption setup failed.", e);
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

            if (!manualSettingsCheckbox.isChecked()) {
                readHeaderAndAutoPopulate();
            }
        }
    }

    private void readHeaderAndAutoPopulate() {
        if (selectedFileUri == null) return;
        String path = copyUriToCache(selectedFileUri);
        if (path == null) {
            logToConsole("Could not read file header: Unable to copy file to cache.");
            return;
        }
        
        try (FileInputStream fis = new FileInputStream(path)) {
            FileHeader header = FileHeader.fromStream(fis);
            CryptoOptions options = header.getOptions();

            autoSetSpinner(protocolSpinner, options.getProtocol());
            updateDependentSpinners();
            autoSetSpinner(keyLengthSpinner, options.getKeyLength());
            autoSetSpinner(blockSizeSpinner, options.getBlockSize());
            autoSetSpinner(modeSpinner, options.getMode());
            updatePaddingAndTagSpinners();
            autoSetSpinner(paddingSpinner, options.getPadding());
            autoSetSpinner(kdfSpinner, options.getKdf());
            if(options.getTagLength() != null) {
                autoSetSpinner(tagLengthSpinner, options.getTagLength());
            }

            logToConsole("Header read successfully. Settings populated.");
            logToConsole("-> " + options.toString());

        } catch (Exception e) {
            logToConsole("Could not read file header: " + e.getMessage());
            // If we can't read the header, force manual mode
            manualSettingsCheckbox.setChecked(true);
            logToConsole("Switched to manual settings mode.");
        }
    }

    private <T> void autoSetSpinner(Spinner spinner, T value) {
        if (value == null) return;
        ArrayAdapter<T> adapter = (ArrayAdapter<T>) spinner.getAdapter();
        if (adapter == null) return;
        for (int i = 0; i < adapter.getCount(); i++) {
            if (value.equals(adapter.getItem(i))) {
                spinner.setSelection(i);
                return;
            }
        }
        logToConsole("Warning: Could not auto-set spinner for value: " + value);
    }

    @Override
    public void onStart(long totalSize) {
        runOnUiThread(() -> {
            setUiEnabled(false);
            consoleTextView.setText("");
            logToConsole("Starting decryption...");
            logToConsole("Total size: " + totalSize + " bytes");
            progressBar.setMax((int) totalSize);
            progressBar.setProgress(0);
            progressBar.setVisibility(View.VISIBLE);
            statusTextView.setVisibility(View.GONE);
        });
    }

    @Override
    public void onProgress(long bytesProcessed, long totalSize) {
        runOnUiThread(() -> progressBar.setProgress((int) bytesProcessed));
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
