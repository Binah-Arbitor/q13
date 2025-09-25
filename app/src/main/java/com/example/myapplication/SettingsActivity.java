
package com.example.myapplication;

import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import androidx.preference.PreferenceFragmentCompat;
import androidx.preference.SwitchPreferenceCompat;

public class SettingsActivity extends AppCompatActivity {

    public static final String PREFS_NAME = "AppSettings";
    public static final String KEY_ADVANCED_MODE = "advanced_mode";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);
        if (savedInstanceState == null) {
            getSupportFragmentManager()
                    .beginTransaction()
                    .replace(R.id.settings_container, new SettingsFragment())
                    .commit();
        }
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }
    }

    public static class SettingsFragment extends PreferenceFragmentCompat {
        @Override
        public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
            getPreferenceManager().setSharedPreferencesName(PREFS_NAME);
            setPreferencesFromResource(R.xml.preferences, rootKey);

            SwitchPreferenceCompat advancedModeSwitch = findPreference(KEY_ADVANCED_MODE);
            if (advancedModeSwitch != null) {
                advancedModeSwitch.setOnPreferenceChangeListener((preference, newValue) -> {
                    // Here you can add any logic to be executed when the switch is toggled
                    return true;
                });
            }
        }
    }

    @Override
    public boolean onSupportNavigateUp() {
        onBackPressed();
        return true;
    }
}
