package org.example;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.*;
import java.nio.charset.StandardCharsets;

public class RSA {

    public PrivateKey privateKey; // maybe make static
    public PublicKey publicKey;

    public RSA(){
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public String encrypt(String message) throws Exception{
        byte[] messageToBytes = message.getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE,this.publicKey);
        byte[] encryptedBytes = cipher.doFinal(messageToBytes);
        return encode(encryptedBytes);
    }

    public String encrypt(String message, PublicKey key) throws Exception{
        byte[] messageToBytes = message.getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE,key);
        byte[] encryptedBytes = cipher.doFinal(messageToBytes);
        return encode(encryptedBytes);
    }

    public String encrypt(String message, PrivateKey key) throws Exception{
        byte[] messageToBytes = message.getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE,key);
        byte[] encryptedBytes = cipher.doFinal(messageToBytes);
        return encode(encryptedBytes);
    }

    private static String encode(byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }

    private static byte[] decode(String data){
        return Base64.getDecoder().decode(data);
    }

    public PublicKey KeyfromString(String Key) throws InvalidKeySpecException, NoSuchAlgorithmException{
        //only public keys
        X509EncodedKeySpec Key_enc = new X509EncodedKeySpec(decode(Key));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pub = keyFactory.generatePublic(Key_enc);
        return pub;
    }

    public static String StringfromKey(PublicKey Key){
        String StrKey = encode(Key.getEncoded());
        return StrKey;
    }

    public String decrypt(String message) throws Exception{
        byte[] encryptedBytes = decode(message);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE,this.privateKey);
        byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
        return new String(decryptedMessage, "UTF8");
    }

    public String decrypt(String message , PublicKey key) throws Exception{
        byte[] encryptedBytes = decode(message);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE,key);
        byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
        return new String(decryptedMessage, "UTF8");
    }

    public String decrypt(String message , PrivateKey key) throws Exception{
        byte[] encryptedBytes = decode(message);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE,key);
        byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
        return new String(decryptedMessage, "UTF8");
    }

    public static void main(String[] args){
        RSA rsa = new RSA();
        //rsa.init_RSA();
        String encMsg = "", decMsg = "";
        String keyStr = StringfromKey(rsa.publicKey);

        System.out.println("Starting....");
        try {
            encMsg = rsa.encrypt("Hello World");
            decMsg = rsa.decrypt(encMsg);

            System.out.println("Encrypted:" + encMsg);
            System.out.println("Decrypted:" + decMsg);
            System.out.println("PublicStr: " + keyStr);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

    }
}

