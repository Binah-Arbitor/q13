package com.example.myapplication;

import android.content.Intent;
import android.os.Bundle;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import com.google.android.material.bottomnavigation.BottomNavigationView;

public class AdvancedDecryptionActivity extends AppCompatActivity {

    private BottomNavigationView bottomNav;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_advanced_decryption);

        bottomNav = findViewById(R.id.bottom_nav);
        setupBottomNav();

        // TODO: Implement advanced decryption logic
        TextView title = findViewById(R.id.title_textview);
        title.setText("Advanced Decryption (Not Implemented)");
    }

    private void setupBottomNav() {
        bottomNav.setSelectedItemId(R.id.nav_advanced_decrypt);
        bottomNav.setOnNavigationItemSelectedListener(item -> {
            int itemId = item.getItemId();
            if (itemId == R.id.nav_simple_encrypt) {
                startActivity(new Intent(this, SimpleEncryptionActivity.class));
                return true;
            } else if (itemId == R.id.nav_advanced_encrypt) {
                startActivity(new Intent(this, AdvancedEncryptionActivity.class));
                return true;
            } else if (itemId == R.id.nav_decrypt) {
                startActivity(new Intent(this, SimpleDecryptionActivity.class));
                return true;
            } else if (itemId == R.id.nav_advanced_decrypt) {
                return true;
            }
            return false;
        });
    }
}
