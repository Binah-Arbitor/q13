package com.example.myapplication;

import android.Manifest;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Toast;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

public abstract class BaseActivity extends AppCompatActivity {

    private ActivityResultLauncher<String[]> requestPermissionsLauncher;
    private Runnable afterPermissionGranted;

    private static final String[] STORAGE_PERMISSIONS;
    static {
        // Android 10 (Q) and above don't need WRITE_EXTERNAL_STORAGE for MediaStore.
        // READ_EXTERNAL_STORAGE is sufficient.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            STORAGE_PERMISSIONS = new String[]{Manifest.permission.READ_EXTERNAL_STORAGE};
        } else {
            STORAGE_PERMISSIONS = new String[]{
                Manifest.permission.READ_EXTERNAL_STORAGE,
                Manifest.permission.WRITE_EXTERNAL_STORAGE
            };
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Register the permissions launcher.
        requestPermissionsLauncher = registerForActivityResult(
            new ActivityResultContracts.RequestMultiplePermissions(),
            permissions -> {
                boolean allGranted = permissions.values().stream().allMatch(g -> g);
                if (allGranted) {
                    if (afterPermissionGranted != null) {
                        afterPermissionGranted.run();
                    }
                }
                afterPermissionGranted = null; // Clear runnable after use
            }
        );
    }

    @Override
    protected void onResume() {
        super.onResume();
        checkModeAndRedirect();
    }

    private void checkModeAndRedirect() {
        SharedPreferences settings = getSharedPreferences(SettingsActivity.PREFS_NAME, MODE_PRIVATE);
        boolean isAdvancedModeFromPrefs = settings.getBoolean(SettingsActivity.KEY_ADVANCED_MODE, false);

        // If the current activity's mode does not match the preference, switch to the correct mode's main screen.
        if (isActivityForAdvancedMode() != isAdvancedModeFromPrefs) {
            Intent intent;
            if (isAdvancedModeFromPrefs) {
                intent = new Intent(this, AdvancedEncryptionActivity.class);
            } else {
                intent = new Intent(this, SimpleEncryptionActivity.class);
            }
            // These flags clear the entire task and start the new activity as a fresh one.
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(intent);
            finish();
        }
    }

    /**
     * Checks for storage permissions. If granted, executes the action. 
     * If not, requests permissions and executes the action upon grant.
     * @param action The runnable to execute after permissions are secured.
     */
    protected void checkPermissionsAndExecute(Runnable action) {
        if (hasStoragePermissions()) {
            action.run();
        } else {
            afterPermissionGranted = action; // Save the action
            requestPermissionsLauncher.launch(STORAGE_PERMISSIONS); // Request permissions
        }
    }

    private boolean hasStoragePermissions() {
        for (String permission : STORAGE_PERMISSIONS) {
            if (ContextCompat.checkSelfPermission(this, permission) != PackageManager.PERMISSION_GRANTED) {
                return false;
            }
        }
        return true;
    }

    // Inflate the options menu
    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main_menu, menu);
        return true;
    }

    // Handle menu item selections
    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == R.id.action_settings) {
            startActivity(new Intent(this, SettingsActivity.class));
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    /**
     * Subclasses must implement this to declare if they belong to the "Advanced" or "Simple" mode.
     * @return true if the activity is for Advanced Mode, false otherwise.
     */
    protected abstract boolean isActivityForAdvancedMode();
}
