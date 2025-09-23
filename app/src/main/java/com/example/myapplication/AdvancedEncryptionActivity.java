package com.example.myapplication;

import android.content.Intent;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import com.google.android.material.bottomnavigation.BottomNavigationView;

public class AdvancedEncryptionActivity extends AppCompatActivity {

    private BottomNavigationView bottomNav;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_advanced_encryption);

        bottomNav = findViewById(R.id.bottom_nav);
        setupBottomNav();
    }

    private void setupBottomNav() {
        bottomNav.setSelectedItemId(R.id.nav_advanced_encrypt);
        bottomNav.setOnNavigationItemSelectedListener(item -> {
            int itemId = item.getItemId();
            if (itemId == R.id.nav_simple_encrypt) {
                startActivity(new Intent(this, SimpleEncryptionActivity.class));
                return true;
            } else if (itemId == R.id.nav_advanced_encrypt) {
                // Already here
                return true;
            } else if (itemId == R.id.nav_decrypt) {
                startActivity(new Intent(this, DecryptActivity.class));
                return true;
            }
            return false;
        });
    }
}
