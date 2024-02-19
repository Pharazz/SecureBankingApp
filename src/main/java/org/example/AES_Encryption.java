package org.example;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;
import java.util.Random;

public class AES_Encryption {

    private static final String ALGORITHM = "AES";
    private static final String HASH_ALGORITHM = "SHA-256";

    public static String generateKey(String password) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
        byte[] keyBytes = digest.digest(password.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(keyBytes);
    }
    public static String generateRandomString(int length) {
        String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        Random RANDOM = new SecureRandom();
        Objects.requireNonNull(length);

        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(CHARACTERS.charAt(RANDOM.nextInt(CHARACTERS.length())));
        }
        return sb.toString();
    }
    public static String encrypt(String message, String key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(key);
        SecretKey secretKey = new SecretKeySpec(keyBytes, ALGORITHM);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String ciphertext, String key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(key);
        SecretKey secretKey = new SecretKeySpec(keyBytes, ALGORITHM);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] decoded = Base64.getDecoder().decode(ciphertext);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
//        String seed = generateRandomString(10);
        String key = generateKey("FILEKEY");
        String message1 = "500000";
        String message2 = "50";
        String message3 = "0";

        String encrypted1 = encrypt(message1, key);
        String encrypted2 = encrypt(message2, key);
        String encrypted3 = encrypt(message3, key);
        System.out.println("Encrypted message: " + encrypted1);
        System.out.println("Encrypted message: " + encrypted2);
        System.out.println("Encrypted message: " + encrypted3);

        String decrypted1 = decrypt(encrypted1, key);
        String decrypted2 = decrypt(encrypted2, key);
        String decrypted3 = decrypt(encrypted3, key);
        System.out.println("Decrypted message: " + decrypted1);
        System.out.println("Decrypted message: " + decrypted2);
        System.out.println("Decrypted message: " + decrypted3);
        System.out.println("Key: " + key);
//        System.out.println("Seed: " + seed);
    }
}


