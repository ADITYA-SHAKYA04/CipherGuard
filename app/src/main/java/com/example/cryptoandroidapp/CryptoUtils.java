package com.example.cryptoandroidapp;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

public class CryptoUtils {
    private static final String AES_GCM_ALIAS = "aes_gcm_key";
    private static final String AES_CBC_ALIAS = "aes_cbc_key";
    private static final String RSA_ALIAS = "rsa_key";
    private static final int GCM_IV_LENGTH = 12;
    private static final int CBC_IV_LENGTH = 16;
    private static final int GCM_TAG_LENGTH = 128;

    // AES-GCM (String)
    public static String encryptAESGCM(Context context, String plainText) throws Exception {
        SecretKey key = getOrCreateAESKey(AES_GCM_ALIAS, KeyProperties.BLOCK_MODE_GCM);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = cipher.getIV();
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
        return Base64.encodeToString(combined, Base64.DEFAULT);
    }

    public static String decryptAESGCM(Context context, String cipherText) throws Exception {
        SecretKey key = getOrCreateAESKey(AES_GCM_ALIAS, KeyProperties.BLOCK_MODE_GCM);
        byte[] combined = Base64.decode(cipherText, Base64.DEFAULT);
        byte[] iv = Arrays.copyOfRange(combined, 0, GCM_IV_LENGTH);
        byte[] encrypted = Arrays.copyOfRange(combined, GCM_IV_LENGTH, combined.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    // AES-GCM (bytes)
    public static byte[] encryptAESGCMBytes(Context context, byte[] plainBytes) throws Exception {
        SecretKey key = getOrCreateAESKey(AES_GCM_ALIAS, KeyProperties.BLOCK_MODE_GCM);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = cipher.getIV();
        byte[] encrypted = cipher.doFinal(plainBytes);
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
        return combined;
    }

    public static byte[] decryptAESGCMBytes(Context context, byte[] cipherBytes) throws Exception {
        SecretKey key = getOrCreateAESKey(AES_GCM_ALIAS, KeyProperties.BLOCK_MODE_GCM);
        byte[] iv = Arrays.copyOfRange(cipherBytes, 0, GCM_IV_LENGTH);
        byte[] encrypted = Arrays.copyOfRange(cipherBytes, GCM_IV_LENGTH, cipherBytes.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(encrypted);
    }

    // AES-CBC (String)
    public static String encryptAESCBC(Context context, String plainText) throws Exception {
        SecretKey key = getOrCreateAESKey(AES_CBC_ALIAS, KeyProperties.BLOCK_MODE_CBC);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = cipher.getIV();
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
        return Base64.encodeToString(combined, Base64.DEFAULT);
    }

    public static String decryptAESCBC(Context context, String cipherText) throws Exception {
        SecretKey key = getOrCreateAESKey(AES_CBC_ALIAS, KeyProperties.BLOCK_MODE_CBC);
        byte[] combined = Base64.decode(cipherText, Base64.DEFAULT);
        byte[] iv = Arrays.copyOfRange(combined, 0, CBC_IV_LENGTH);
        byte[] encrypted = Arrays.copyOfRange(combined, CBC_IV_LENGTH, combined.length);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        IvParameterSpec spec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    // AES-CBC (bytes)
    public static byte[] encryptAESCBCBytes(Context context, byte[] plainBytes) throws Exception {
        SecretKey key = getOrCreateAESKey(AES_CBC_ALIAS, KeyProperties.BLOCK_MODE_CBC);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = cipher.getIV();
        byte[] encrypted = cipher.doFinal(plainBytes);
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
        return combined;
    }

    public static byte[] decryptAESCBCBytes(Context context, byte[] cipherBytes) throws Exception {
        SecretKey key = getOrCreateAESKey(AES_CBC_ALIAS, KeyProperties.BLOCK_MODE_CBC);
        byte[] iv = Arrays.copyOfRange(cipherBytes, 0, CBC_IV_LENGTH);
        byte[] encrypted = Arrays.copyOfRange(cipherBytes, CBC_IV_LENGTH, cipherBytes.length);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        IvParameterSpec spec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(encrypted);
    }

    // AES-PBKDF2 (String)
    public static String encryptAESPBKDF2(String plainText, String password) throws Exception {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 100000, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new javax.crypto.spec.SecretKeySpec(tmp.getEncoded(), "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secret, gcmSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.encodeToString(salt, Base64.NO_WRAP) + ":" +
               Base64.encodeToString(iv, Base64.NO_WRAP) + ":" +
               Base64.encodeToString(encrypted, Base64.NO_WRAP);
    }

    public static String decryptAESPBKDF2(String cipherText, String password) throws Exception {
        String[] parts = cipherText.split(":");
        if (parts.length != 3) throw new IllegalArgumentException("Invalid PBKDF2 ciphertext format");
        byte[] salt = Base64.decode(parts[0], Base64.NO_WRAP);
        byte[] iv = Base64.decode(parts[1], Base64.NO_WRAP);
        byte[] encrypted = Base64.decode(parts[2], Base64.NO_WRAP);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 100000, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new javax.crypto.spec.SecretKeySpec(tmp.getEncoded(), "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secret, gcmSpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    // AES-PBKDF2 (bytes)
    public static byte[] encryptAESPBKDF2Bytes(byte[] plainBytes, String password) throws Exception {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 100000, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new javax.crypto.spec.SecretKeySpec(tmp.getEncoded(), "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secret, gcmSpec);
        byte[] encrypted = cipher.doFinal(plainBytes);
        byte[] out = new byte[salt.length + iv.length + encrypted.length];
        System.arraycopy(salt, 0, out, 0, salt.length);
        System.arraycopy(iv, 0, out, salt.length, iv.length);
        System.arraycopy(encrypted, 0, out, salt.length + iv.length, encrypted.length);
        return out;
    }

    public static byte[] decryptAESPBKDF2Bytes(byte[] cipherBytes, String password) throws Exception {
        byte[] salt = Arrays.copyOfRange(cipherBytes, 0, 16);
        byte[] iv = Arrays.copyOfRange(cipherBytes, 16, 16 + GCM_IV_LENGTH);
        byte[] encrypted = Arrays.copyOfRange(cipherBytes, 16 + GCM_IV_LENGTH, cipherBytes.length);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 100000, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new javax.crypto.spec.SecretKeySpec(tmp.getEncoded(), "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secret, gcmSpec);
        return cipher.doFinal(encrypted);
    }

    // RSA-OAEP (String, hybrid)
    public static String encryptRSAOAEP(Context context, String plainText) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
        byte[] encryptedData = aesCipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        PublicKey publicKey = getOrCreateRSAKeyPair().getPublic();
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());
        String out = encryptedAesKey.length + ":" +
                Base64.encodeToString(encryptedAesKey, Base64.NO_WRAP) + ":" +
                Base64.encodeToString(iv, Base64.NO_WRAP) + ":" +
                Base64.encodeToString(encryptedData, Base64.NO_WRAP);
        return out;
    }

    public static String decryptRSAOAEP(Context context, String cipherText) throws Exception {
        String[] parts = cipherText.split(":");
        if (parts.length != 4) throw new IllegalArgumentException("Invalid hybrid RSA ciphertext format");
        int aesKeyLen = Integer.parseInt(parts[0]);
        byte[] encryptedAesKey = Base64.decode(parts[1], Base64.NO_WRAP);
        byte[] iv = Base64.decode(parts[2], Base64.NO_WRAP);
        byte[] encryptedData = Base64.decode(parts[3], Base64.NO_WRAP);
        PrivateKey privateKey = getOrCreateRSAKeyPair().getPrivate();
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);
        SecretKey aesKey = new javax.crypto.spec.SecretKeySpec(aesKeyBytes, "AES");
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
        byte[] decrypted = aesCipher.doFinal(encryptedData);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    // RSA-OAEP (bytes, hybrid)
    public static byte[] encryptRSAOAEPBytes(Context context, byte[] plainBytes) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
        byte[] encryptedData = aesCipher.doFinal(plainBytes);
        PublicKey publicKey = getOrCreateRSAKeyPair().getPublic();
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());
        java.nio.ByteBuffer buffer = java.nio.ByteBuffer.allocate(4 + encryptedAesKey.length + iv.length + encryptedData.length);
        buffer.putInt(encryptedAesKey.length);
        buffer.put(encryptedAesKey);
        buffer.put(iv);
        buffer.put(encryptedData);
        return buffer.array();
    }

    public static byte[] decryptRSAOAEPBytes(Context context, byte[] cipherBytes) throws Exception {
        java.nio.ByteBuffer buffer = java.nio.ByteBuffer.wrap(cipherBytes);
        int aesKeyLen = buffer.getInt();
        byte[] encryptedAesKey = new byte[aesKeyLen];
        buffer.get(encryptedAesKey);
        byte[] iv = new byte[GCM_IV_LENGTH];
        buffer.get(iv);
        byte[] encryptedData = new byte[buffer.remaining()];
        buffer.get(encryptedData);
        PrivateKey privateKey = getOrCreateRSAKeyPair().getPrivate();
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);
        SecretKey aesKey = new javax.crypto.spec.SecretKeySpec(aesKeyBytes, "AES");
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
        return aesCipher.doFinal(encryptedData);
    }

    // Key management
    private static SecretKey getOrCreateAESKey(String alias, String blockMode) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (!keyStore.containsAlias(alias)) {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(blockMode)
                    .setEncryptionPaddings(blockMode.equals(KeyProperties.BLOCK_MODE_GCM) ? KeyProperties.ENCRYPTION_PADDING_NONE : KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setKeySize(256);
            keyGenerator.init(builder.build());
            keyGenerator.generateKey();
        }
        return ((SecretKey) keyStore.getKey(alias, null));
    }

    private static KeyPair getOrCreateRSAKeyPair() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (!keyStore.containsAlias(RSA_ALIAS)) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            kpg.initialize(new KeyGenParameterSpec.Builder(RSA_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(2048)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .build());
            kpg.generateKeyPair();
        }
        KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(RSA_ALIAS, null);
        return new KeyPair(entry.getCertificate().getPublicKey(), entry.getPrivateKey());
    }
}
