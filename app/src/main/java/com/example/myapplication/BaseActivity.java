package com.example.myapplication;

import android.Manifest;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.Settings;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Toast;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import java.util.Map;

public abstract class BaseActivity extends AppCompatActivity {

    private ActivityResultLauncher<String[]> requestPermissionsLauncher;
    private ActivityResultLauncher<Intent> manageStorageLauncher;
    private Runnable afterPermissionGranted;

    // Permissions for Android 9 and below
    private static final String[] LEGACY_STORAGE_PERMISSIONS = new String[]{
        Manifest.permission.READ_EXTERNAL_STORAGE,
        Manifest.permission.WRITE_EXTERNAL_STORAGE
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Launcher for standard runtime permissions (for Android 10 and below)
        requestPermissionsLauncher = registerForActivityResult(
            new ActivityResultContracts.RequestMultiplePermissions(),
            (Map<String, Boolean> permissions) -> {
                boolean allGranted = permissions.values().stream().allMatch(g -> g);
                if (allGranted) {
                    if (afterPermissionGranted != null) afterPermissionGranted.run();
                } else {
                    Toast.makeText(this, "Storage permissions are required to select a file.", Toast.LENGTH_LONG).show();
                }
                afterPermissionGranted = null;
            }
        );

        // Launcher for opening the 'All files access' settings screen (for Android 11+)
        manageStorageLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            result -> {
                // After returning from settings, check if permission was granted
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    if (Environment.isExternalStorageManager()) {
                        if (afterPermissionGranted != null) afterPermissionGranted.run();
                    } else {
                        Toast.makeText(this, "'All files access' permission is required for full functionality.", Toast.LENGTH_LONG).show();
                    }
                    afterPermissionGranted = null;
                }
            }
        );
    }

    protected void checkPermissionsAndExecute(Runnable action) {
        this.afterPermissionGranted = action;
        if (hasStoragePermissions()) {
            action.run();
        } else {
            requestStoragePermissions();
        }
    }

    private boolean hasStoragePermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // On Android 11+, check for 'All files access'
            return Environment.isExternalStorageManager();
        } else {
            // On Android 10 and below, check for legacy read/write permissions
            for (String permission : LEGACY_STORAGE_PERMISSIONS) {
                if (ContextCompat.checkSelfPermission(this, permission) != PackageManager.PERMISSION_GRANTED) {
                    return false;
                }
            }
            return true;
        }
    }

    private void requestStoragePermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // On Android 11+, guide user to the settings screen
            try {
                Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                intent.setData(Uri.parse("package:" + getApplicationContext().getPackageName()));
                Toast.makeText(this, "Please enable 'All files access' to proceed.", Toast.LENGTH_LONG).show();
                manageStorageLauncher.launch(intent);
            } catch (Exception e) {
                // Fallback for devices that might not have this screen
                Intent intent = new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION);
                manageStorageLauncher.launch(intent);
            }
        } else {
            // On Android 10 and below, request legacy permissions directly
            requestPermissionsLauncher.launch(LEGACY_STORAGE_PERMISSIONS);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        checkModeAndRedirect();
    }

    private void checkModeAndRedirect() {
        SharedPreferences settings = getSharedPreferences(SettingsActivity.PREFS_NAME, MODE_PRIVATE);
        boolean isAdvancedModeFromPrefs = settings.getBoolean(SettingsActivity.KEY_ADVANCED_MODE, false);

        if (isActivityForAdvancedMode() != isAdvancedModeFromPrefs) {
            Intent intent;
            if (isAdvancedModeFromPrefs) {
                intent = new Intent(this, AdvancedEncryptionActivity.class);
            } else {
                intent = new Intent(this, SimpleEncryptionActivity.class);
            }
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(intent);
            finish();
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main_menu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == R.id.action_settings) {
            startActivity(new Intent(this, SettingsActivity.class));
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    protected abstract boolean isActivityForAdvancedMode();
}
