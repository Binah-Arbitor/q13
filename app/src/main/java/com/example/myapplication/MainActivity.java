package com.example.myapplication;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Check the saved mode and launch the appropriate activity immediately.
        SharedPreferences settings = getSharedPreferences(SettingsActivity.PREFS_NAME, MODE_PRIVATE);
        boolean isAdvancedMode = settings.getBoolean(SettingsActivity.KEY_ADVANCED_MODE, false);

        Intent intent;
        if (isAdvancedMode) {
            intent = new Intent(MainActivity.this, AdvancedEncryptionActivity.class);
        } else {
            intent = new Intent(MainActivity.this, SimpleEncryptionActivity.class);
        }

        startActivity(intent);
        finish(); // Finish this activity so the user can't navigate back to it.
    }
}
