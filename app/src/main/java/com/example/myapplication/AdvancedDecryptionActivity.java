package com.example.myapplication;

import android.content.Intent;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import com.example.myapplication.crypto.CryptoListener;
import com.google.android.material.bottomnavigation.BottomNavigationView;

public class AdvancedDecryptionActivity extends AppCompatActivity implements CryptoListener {

    private BottomNavigationView bottomNav;
    private int lastProgress = -1;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_advanced_decryption);

        bottomNav = findViewById(R.id.bottom_nav);
        setupBottomNav();

        TextView title = findViewById(R.id.title_textview);
        title.setText("Advanced Decryption (Not Implemented)");
        
        // Since this feature is not implemented, show a toast message.
        Toast.makeText(this, "This feature is not yet available.", Toast.LENGTH_LONG).show();
    }

    private void setupBottomNav() {
        // This screen is not a main destination, so no item is selected.
        bottomNav.setOnNavigationItemSelectedListener(item -> {
            int itemId = item.getItemId();
            if (itemId == R.id.nav_encrypt) {
                startActivity(new Intent(this, SimpleEncryptionActivity.class));
                return true;
            } else if (itemId == R.id.nav_decrypt) {
                startActivity(new Intent(this, SimpleDecryptionActivity.class));
                return true;
            }
            return false;
        });
    }

    // --- CryptoListener Implementation (empty stubs as it's not implemented) ---

    @Override
    public void onProgress(int progress) {
        // Not used
        lastProgress = progress;
    }

    @Override
    public int getLastReportedProgress() {
        return lastProgress;
    }

    @Override
    public void onSuccess(String result) {
        // Not used
    }

    @Override
    public void onError(String errorMessage) {
        // Not used
    }

    @Override
    public void onLog(String logMessage) {
        // Not used
    }
}
