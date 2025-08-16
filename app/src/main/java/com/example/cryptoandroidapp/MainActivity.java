package com.example.cryptoandroidapp;

import android.os.Bundle;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

public class MainActivity extends AppCompatActivity {
    private EditText inputText;
    private Spinner algorithmSpinner;
    private Button encryptButton, decryptButton;
    private TextView outputText;
    private android.widget.ImageButton copyButton;
    private android.widget.ImageButton themeToggleButton;
    private EditText passwordText;
    private TextView passwordLabel, passwordHelper;
    private Button chooseFileButton;
    private android.net.Uri selectedFileUri;
    private TextView selectedFileName;

    private static final String[] ALGORITHMS = {"AES-GCM", "AES-CBC", "RSA-OAEP"};

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        inputText = findViewById(R.id.inputText);
        algorithmSpinner = findViewById(R.id.algorithmSpinner);
        encryptButton = findViewById(R.id.encryptButton);
        decryptButton = findViewById(R.id.decryptButton);
        outputText = findViewById(R.id.outputText);
        copyButton = findViewById(R.id.copyButton);
        themeToggleButton = findViewById(R.id.themeToggleButton);
        passwordText = findViewById(R.id.passwordText);
        passwordLabel = findViewById(R.id.passwordLabel);
        passwordHelper = findViewById(R.id.passwordHelper);
        chooseFileButton = findViewById(R.id.chooseFileButton);
        selectedFileName = findViewById(R.id.selectedFileName);
        chooseFileButton.setOnClickListener(v -> launchFilePicker());
        Button helpButton = findViewById(R.id.helpButton);
        Button encryptFileButton = findViewById(R.id.encryptFileButton);
        Button decryptFileButton = findViewById(R.id.decryptFileButton);
        themeToggleButton.setOnClickListener(v -> toggleTheme());

        // Password visibility toggle using drawableEnd
        passwordText.setOnTouchListener((v, event) -> {
            final int DRAWABLE_END = 2; // Right drawable
            if (event.getAction() == android.view.MotionEvent.ACTION_UP) {
                if (event.getRawX() >= (passwordText.getRight() - passwordText.getCompoundDrawables()[DRAWABLE_END].getBounds().width())) {
                    if (passwordText.getInputType() == (android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD)) {
                        passwordText.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
                        passwordText.setCompoundDrawablesWithIntrinsicBounds(0, 0, android.R.drawable.ic_menu_close_clear_cancel, 0);
                    } else {
                        passwordText.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
                        passwordText.setCompoundDrawablesWithIntrinsicBounds(0, 0, android.R.drawable.ic_menu_view, 0);
                    }
                    passwordText.setSelection(passwordText.getText().length());
                    return true;
                }
            }
            return false;
        });

        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, ALGORITHMS);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        algorithmSpinner.setAdapter(adapter);

        encryptButton.setOnClickListener(v -> handleEncrypt());
        decryptButton.setOnClickListener(v -> handleDecrypt());
        copyButton.setOnClickListener(v -> handleCopyOutput());
        helpButton.setOnClickListener(v -> showSecurityTipsDialog());
        encryptFileButton.setOnClickListener(v -> handleEncryptFile());
        decryptFileButton.setOnClickListener(v -> handleDecryptFile());

        updateThemeToggleIcon();
    } // End of onCreate method

    // Launch Android file picker
    private void launchFilePicker() {
        android.content.Intent intent = new android.content.Intent(android.content.Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(android.content.Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        startActivityForResult(intent, 1001);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, android.content.Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 1001 && resultCode == RESULT_OK && data != null) {
            selectedFileUri = data.getData();
            if (selectedFileUri != null) {
                String fileName = getFileName(selectedFileUri);
                chooseFileButton.setText("Change File");
                selectedFileName.setText("Selected: " + fileName);
            }
        }
    }

    // Helper to get file name from Uri
    private String getFileName(android.net.Uri uri) {
        String result = null;
        if (uri.getScheme().equals("content")) {
            android.database.Cursor cursor = getContentResolver().query(uri, null, null, null, null);
            try {
                if (cursor != null && cursor.moveToFirst()) {
                    int idx = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME);
                    if (idx >= 0) result = cursor.getString(idx);
                }
            } finally {
                if (cursor != null) cursor.close();
            }
        }
        if (result == null) {
            result = uri.getPath();
            int cut = result.lastIndexOf('/');
            if (cut != -1) {
                result = result.substring(cut + 1);
            }
        }
        return result;
    }

    // Moved handleCopyOutput() here
    private void handleCopyOutput() {
        String text = outputText.getText().toString();
        android.view.View rootView = findViewById(android.R.id.content);
        if (!text.isEmpty()) {
            android.content.ClipboardManager clipboard = (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            android.content.ClipData clip = android.content.ClipData.newPlainText("Encrypted/Decrypted Output", text);
            clipboard.setPrimaryClip(clip);
            com.google.android.material.snackbar.Snackbar.make(rootView, "Output copied to clipboard", com.google.android.material.snackbar.Snackbar.LENGTH_SHORT).show();
        } else {
            com.google.android.material.snackbar.Snackbar.make(rootView, "No output to copy", com.google.android.material.snackbar.Snackbar.LENGTH_SHORT).show();
        }
    }

    private void handleEncrypt() {
        String plainText = inputText.getText().toString();
        String algorithm = algorithmSpinner.getSelectedItem().toString();
        String password = passwordText.getText().toString();
        try {
            String cipherText = "";
            switch (algorithm) {
                case "AES-GCM":
                    if (!password.isEmpty()) {
                        cipherText = CryptoUtils.encryptAESPBKDF2(plainText, password);
                    } else {
                        cipherText = CryptoUtils.encryptAESGCM(this, plainText);
                    }
                    break;
                case "AES-CBC":
                    if (!password.isEmpty()) {
                        cipherText = CryptoUtils.encryptAESPBKDF2(plainText, password);
                    } else {
                        cipherText = CryptoUtils.encryptAESCBC(this, plainText);
                    }
                    break;
                case "RSA-OAEP":
                    cipherText = CryptoUtils.encryptRSAOAEP(this, plainText);
                    break;
            }
            outputText.setText(cipherText);
        } catch (Exception e) {
            outputText.setText("Encryption error: " + e.getMessage());
        }
    }

    private void handleDecrypt() {
        String cipherText = inputText.getText().toString();
        String algorithm = algorithmSpinner.getSelectedItem().toString();
        String password = passwordText.getText().toString();
        try {
            String plainText = "";
            switch (algorithm) {
                case "AES-GCM":
                    if (!password.isEmpty()) {
                        plainText = CryptoUtils.decryptAESPBKDF2(cipherText, password);
                    } else {
                        plainText = CryptoUtils.decryptAESGCM(this, cipherText);
                    }
                    break;
                case "AES-CBC":
                    if (!password.isEmpty()) {
                        plainText = CryptoUtils.decryptAESPBKDF2(cipherText, password);
                    } else {
                        plainText = CryptoUtils.decryptAESCBC(this, cipherText);
                    }
                    break;
                case "RSA-OAEP":
                    plainText = CryptoUtils.decryptRSAOAEP(this, cipherText);
                    break;
            }
            outputText.setText(plainText);
        } catch (Exception e) {
            outputText.setText("Decryption error: " + e.getMessage());
        }
    }

    private String appendSuffixToFileName(String fileName, String suffix) {
        int dotIndex = fileName.lastIndexOf('.');
        if (dotIndex == -1) {
            return fileName + suffix;
        } else {
            // Insert suffix before extension, e.g. image_encrypted.png
            String name = fileName.substring(0, dotIndex);
            String ext = fileName.substring(dotIndex); // includes the dot
            return name + suffix + ext;
        }
    }

    // File encryption handler
    private void handleEncryptFile() {
        if (selectedFileUri == null) {
            showSnackbar("Please choose a file first.");
            selectedFileName.setText("No file selected");
            return;
        }
        String algorithm = algorithmSpinner.getSelectedItem().toString();
        String password = passwordText.getText().toString();
        try {
            byte[] fileBytes = readFileBytes(selectedFileUri);
            byte[] encryptedBytes = null;
            switch (algorithm) {
                case "AES-GCM":
                    if (!password.isEmpty()) {
                        encryptedBytes = CryptoUtils.encryptAESPBKDF2Bytes(fileBytes, password);
                    } else {
                        encryptedBytes = CryptoUtils.encryptAESGCMBytes(this, fileBytes);
                    }
                    break;
                case "AES-CBC":
                    if (!password.isEmpty()) {
                        encryptedBytes = CryptoUtils.encryptAESPBKDF2Bytes(fileBytes, password);
                    } else {
                        encryptedBytes = CryptoUtils.encryptAESCBCBytes(this, fileBytes);
                    }
                    break;
                case "RSA-OAEP":
                    encryptedBytes = CryptoUtils.encryptRSAOAEPBytes(this, fileBytes);
                    break;
            }
            String originalFileName = getFileName(selectedFileUri);
            String newFileName = appendSuffixToFileName(originalFileName, "_encrypted");
            String mimeType = getContentResolver().getType(selectedFileUri);
            android.net.Uri newFileUri = createNewFileWithMime(newFileName, mimeType);
            writeFileBytes(newFileUri, encryptedBytes);
            showSnackbar("Encrypted file saved as: " + newFileName);
            selectedFileName.setText("Saved: " + newFileName);
        } catch (Exception e) {
            showSnackbar("Encryption error: " + e.getMessage());
        }
    }

    // File decryption handler
    private void handleDecryptFile() {
        if (selectedFileUri == null) {
            showSnackbar("Please choose a file first.");
            selectedFileName.setText("No file selected");
            return;
        }
        String algorithm = algorithmSpinner.getSelectedItem().toString();
        String password = passwordText.getText().toString();
        try {
            byte[] fileBytes = readFileBytes(selectedFileUri);
            byte[] decryptedBytes = null;
            switch (algorithm) {
                case "AES-GCM":
                    if (!password.isEmpty()) {
                        decryptedBytes = CryptoUtils.decryptAESPBKDF2Bytes(fileBytes, password);
                    } else {
                        decryptedBytes = CryptoUtils.decryptAESGCMBytes(this, fileBytes);
                    }
                    break;
                case "AES-CBC":
                    if (!password.isEmpty()) {
                        decryptedBytes = CryptoUtils.decryptAESPBKDF2Bytes(fileBytes, password);
                    } else {
                        decryptedBytes = CryptoUtils.decryptAESCBCBytes(this, fileBytes);
                    }
                    break;
                case "RSA-OAEP":
                    decryptedBytes = CryptoUtils.decryptRSAOAEPBytes(this, fileBytes);
                    break;
            }
            String originalFileName = getFileName(selectedFileUri);
            String newFileName = appendSuffixToFileName(originalFileName, "_decrypted");
            String mimeType = getContentResolver().getType(selectedFileUri);
            android.net.Uri newFileUri = createNewFileWithMime(newFileName, mimeType);
            writeFileBytes(newFileUri, decryptedBytes);
            showSnackbar("Decrypted file saved as: " + newFileName);
            selectedFileName.setText("Saved: " + newFileName);
        } catch (Exception e) {
            showSnackbar("Decryption error: " + e.getMessage());
        }
    }

    // Helper to create a new file in the same directory with MIME type
    private android.net.Uri createNewFileWithMime(String fileName, String mimeType) throws java.io.IOException {
        android.content.ContentValues values = new android.content.ContentValues();
        values.put(android.provider.MediaStore.Files.FileColumns.DISPLAY_NAME, fileName);
        values.put(android.provider.MediaStore.Files.FileColumns.MIME_TYPE, mimeType != null ? mimeType : "application/octet-stream");
        android.net.Uri collection = android.provider.MediaStore.Files.getContentUri("external");
        android.net.Uri newFileUri = getContentResolver().insert(collection, values);
        return newFileUri;
    }

    // Helper to read file bytes
    private byte[] readFileBytes(android.net.Uri uri) throws java.io.IOException {
        java.io.InputStream inputStream = getContentResolver().openInputStream(uri);
        byte[] bytes = new byte[inputStream.available()];
        inputStream.read(bytes);
        inputStream.close();
        return bytes;
    }

    // Helper to write file bytes
    private void writeFileBytes(android.net.Uri uri, byte[] bytes) throws java.io.IOException {
        java.io.OutputStream outputStream = getContentResolver().openOutputStream(uri);
        outputStream.write(bytes);
        outputStream.close();
    }

    // Helper to show snackbar
    private void showSnackbar(String message) {
        android.view.View rootView = findViewById(android.R.id.content);
        com.google.android.material.snackbar.Snackbar.make(rootView, message, com.google.android.material.snackbar.Snackbar.LENGTH_SHORT).show();
    }

    private void toggleTheme() {
        updateThemeToggleIcon();
        int currentNightMode = getResources().getConfiguration().uiMode & android.content.res.Configuration.UI_MODE_NIGHT_MASK;
        if (currentNightMode == android.content.res.Configuration.UI_MODE_NIGHT_YES) {
            androidx.appcompat.app.AppCompatDelegate.setDefaultNightMode(androidx.appcompat.app.AppCompatDelegate.MODE_NIGHT_NO);
            animateThemeToggle(R.drawable.outline_brightness_7_24);
        } else {
            androidx.appcompat.app.AppCompatDelegate.setDefaultNightMode(androidx.appcompat.app.AppCompatDelegate.MODE_NIGHT_YES);
            animateThemeToggle(R.drawable.outline_bedtime_24);
        }
    }
    private void animateThemeToggle(int drawableRes) {
        if (themeToggleButton != null) {
            themeToggleButton.animate().rotationBy(180f).setDuration(300).withEndAction(() -> {
                themeToggleButton.setImageResource(drawableRes);
                themeToggleButton.setRotation(0f);
            }).start();
        }
    }

    private void updateThemeToggleIcon() {
        int currentNightMode = getResources().getConfiguration().uiMode & android.content.res.Configuration.UI_MODE_NIGHT_MASK;
        if (themeToggleButton != null) {
            if (currentNightMode == android.content.res.Configuration.UI_MODE_NIGHT_YES) {
                themeToggleButton.setImageResource(R.drawable.outline_bedtime_24);
            } else {
                themeToggleButton.setImageResource(R.drawable.outline_brightness_7_24);
            }
        }
    }

    private void showSecurityTipsDialog() {
        new androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Security Tips & Algorithm Info")
            .setMessage("• AES-GCM: Recommended for most use cases. Provides authentication and confidentiality.\n\n" +
                       "• AES-CBC: Use only if GCM is not available. Requires random IV.\n\n" +
                       "• RSA-OAEP: Use for encrypting small data or keys. For large data, use hybrid encryption.\n\n" +
                       "• AES-PBKDF2: Use a strong password. Key is derived using PBKDF2 for password-based encryption.\n\n" +
                       "General Tips:\n- Never share your keys or passwords.\n- Use long, random passwords.\n- Prefer device keystore for key storage.\n- Always keep your app updated for security patches.")
            .setPositiveButton("OK", null)
            .show();
    }
}
