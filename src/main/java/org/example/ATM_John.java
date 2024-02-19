package org.example;

import java.io.*;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

public class ATM_John {
    private Socket socket;
    private static Set<byte[]> usedNonces = new HashSet<>();
    private static AES_Encryption aes = new AES_Encryption();
    private RSA rsa = new RSA();
    private BufferedReader bufferedReader;
    private BufferedWriter bufferedWriter;
    private String username;
    private String password;
    private String accNum;
    private String currBalance;
    private String sessionKey;
    private PublicKey serPub;
    public ATM_John(Socket socket, String username, String password){
        try{
            this.socket = socket;
            this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            this.username = username;
            this.password = password;
        }catch (IOException e){
            closeCon(this.socket, this.bufferedReader, this.bufferedWriter);
        }
    }

    public void closeCon(Socket socket, BufferedReader bufferedReader, BufferedWriter bufferedWriter){
        try{
            if (bufferedReader != null){
                bufferedReader.close();
            }
            if (bufferedWriter != null){
                bufferedWriter.close();
            }
            if (socket != null){
                socket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public void sendMSG(String msg) throws IOException {
        this.bufferedWriter.write(msg);
        this.bufferedWriter.newLine();
        this.bufferedWriter.flush();
        return;
    }
    private static byte[] addNonce(byte[] message, byte[] nonce) {
        // Concatenate the nonce and message into a single byte array
        byte[] result = new byte[nonce.length + message.length];
        System.arraycopy(nonce, 0, result, 0, nonce.length);
        System.arraycopy(message, 0, result, nonce.length, message.length);
//        System.arraycopy(message, 0, result, nonce.length, result.length);
        return result;
    }

    private static boolean isValidNonce(byte[] nonce) {
        if (usedNonces.contains(nonce)) {
            return false; // Nonce has already been used, reject message
        } else {
            usedNonces.add(nonce);
            return true;
        }
    }
    public String prepMSG(String Message, byte[] Nonce){
        String MessageStr;
        byte[] MessageByte = addNonce(Message.getBytes(), Nonce);
        MessageStr = Base64.getEncoder().encodeToString(MessageByte);
        return MessageStr;
    }
    public static String bytesToHex(byte[] bytes) {
        char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = HEX_ARRAY[v >>> 4];
            hexChars[i * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }

    public static byte[] generateNonce() {
        byte[] nonce = new byte[15];
        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);
        return nonce;
    }

    public static boolean isEqualNonce(byte[] nonce1, byte[] nonce2) {
        if (nonce1.length != nonce2.length) {
            return false;
        }
        for (int i = 0; i < nonce1.length; i++) {
            if (nonce1[i] != nonce2[i]) {
                return false;
            }
        }
        return true;
    }

    private static String[] receiveNonce(String cipher) {
        byte[] message = Base64.getDecoder().decode(cipher);
        String[] NonceMessage = new String[2];
        // Extract the nonce from the beginning of the message
        byte[] nonce = Arrays.copyOfRange(message, 0, 15);
        // Extract the actual message data after the nonce
        byte[] data = Arrays.copyOfRange(message, 15, message.length);
        // Verify the nonce against a list of recently used nonces
        if (isValidNonce(nonce)) {
            // Process the message data
//            NonceMessage[0] = Base64.getEncoder().encodeToString(nonce);
//            NonceMessage[1] = Base64.getEncoder().encodeToString(data);

            NonceMessage[0] = bytesToHex(nonce);
            NonceMessage[1] = new String(data);
        } else {
            // Nonce is invalid, reject the message
            System.out.println("Invalid nonce, message rejected");
        }
        return NonceMessage;
    }

    public void exchangePublicKeys() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        System.out.println("Beginning Public Key Exchange");
        String keyStr = RSA.StringfromKey(this.rsa.publicKey); //Public Key into String
        this.sendMSG(keyStr);//Send Public Key as String
        this.sendMSG(keyStr);//Send Public Key as String
        System.out.println("Sent Key: " + keyStr);
        System.out.println("Sent PublicKey to ATM");
        keyStr = this.bufferedReader.readLine();
        System.out.println("Received Key: " + keyStr);
        System.out.println("Received Public Key from ATM");
        this.serPub =  rsa.KeyfromString(keyStr);
    }

    public String sessionEncrypt(String content) throws Exception {
        return AES_Encryption.encrypt(content, this.sessionKey);
    }

    public String sessionDecrypt(String cipher) throws Exception {
        return AES_Encryption.decrypt(cipher, this.sessionKey);
    }

    public static boolean validWithdraw(String num1, String num2) {
        boolean verdict = true;
        int n1 = Integer.parseInt(num1);
        int n2 = Integer.parseInt(num2);
        if (n1 < n2){
            verdict = false;
        }
        return verdict;
    }

    public void uiDashes(){
        System.out.println("------------------------------------------------------------");
    }

    public static String subStrings(String num1, String num2) {
        int n1 = Integer.parseInt(num1);
        int n2 = Integer.parseInt(num2);
        int sum = n1 - n2;
        if (sum < 0){
            sum = 0;
        }
        return Integer.toString(sum);
    }

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        String incomingMSG, incomingMSG2, ciphertext;
        String[] NonceMessage = new String[2];
        byte[] genNonce;
        String usrName = "John";
        String psswd = "Bazinga123";
        /*System.out.println("Enter your Username");
        String usrName = scanner.nextLine();
        System.out.println("Enter your Password");
        String psswd = scanner.nextLine();*/
        Socket socket = new Socket("localhost", 1234);
        ATM_John atm = new ATM_John(socket, usrName, psswd);//make the ATM
        while (socket.isConnected()){
            System.out.println("Beginning Authentication");
            atm.exchangePublicKeys();//Advertise Public Key
//            scanner.nextLine();
            atm.sendMSG("ATM 1");//send ATM ID
            incomingMSG = atm.bufferedReader.readLine(); //Get serverID and Nonce
            System.out.println("Received Message");
            System.out.println("Message: " + incomingMSG);
            ciphertext = atm.rsa.decrypt(incomingMSG, atm.rsa.privateKey);//Decrypt it
            System.out.println("Ciphertext: " + ciphertext);
            NonceMessage = receiveNonce(ciphertext);//Seperate and verify nonce
            System.out.println("Received server ID: " + NonceMessage[1]);
            System.out.println("Nonce: "+NonceMessage[0]);
            //Send Nonce back and nonce for next communication
            genNonce = generateNonce();
            ciphertext = atm.prepMSG(Base64.getEncoder().encodeToString(genNonce), hexToBytes(NonceMessage[0]));
            ciphertext = atm.rsa.encrypt(ciphertext, atm.serPub);
            atm.sendMSG(ciphertext);
            System.out.println("Authentication Complete");
            genNonce = generateNonce();//Send client data
            ciphertext = atm.prepMSG(usrName, genNonce);
            ciphertext = atm.rsa.encrypt(ciphertext, atm.serPub);
            atm.sendMSG(ciphertext);//username and nonce
            atm.sendMSG(atm.rsa.encrypt(psswd, atm.serPub));//password
            System.out.println("Sent Client Info");
            //wait for session key and account number
            incomingMSG = atm.bufferedReader.readLine();//session key and nonce
            incomingMSG2 = atm.bufferedReader.readLine();//account number
            ciphertext = atm.rsa.decrypt(incomingMSG, atm.rsa.privateKey);
            NonceMessage = receiveNonce(ciphertext);
            System.out.println("Received session key");
            System.out.println(NonceMessage[1]);
            atm.sessionKey = NonceMessage[1];
            System.out.println("Decrypting with session key");
            atm.accNum = AES_Encryption.decrypt(incomingMSG2, atm.sessionKey);
            System.out.println("Displaying Account: " + atm.accNum);
            //send initial balance request
            genNonce = generateNonce();
            ciphertext = atm.prepMSG("getBal", genNonce);
            ciphertext = AES_Encryption.encrypt(ciphertext,atm.sessionKey);
            atm.sendMSG(ciphertext);
//            System.out.println("Sent Balance Request");
            incomingMSG = atm.bufferedReader.readLine();
            ciphertext = AES_Encryption.decrypt(incomingMSG, atm.sessionKey);
            NonceMessage = receiveNonce(ciphertext);
            atm.currBalance = NonceMessage[1];

            while(socket.isConnected() && !(socket.isClosed())){
                System.out.println("\n\n");
                atm.uiDashes();
                atm.uiDashes();
                System.out.println("Account Number: " +atm.accNum +
                        "\nCurrent Balance: $" + atm.currBalance +
                        "\nChoose your action:\n(1) Balance Query\t" +
                        "(2) Make Deposit\t" +
                        "(3) Make Withdrawl");
                switch (scanner.nextLine()) {
                    case "1","getBal", "getBalance", "Balance" -> {
                        atm.uiDashes();
                        System.out.println("Updating Balance");
                        atm.uiDashes();
                        genNonce = generateNonce();
                        ciphertext = atm.prepMSG("getBal", genNonce);
                        ciphertext = AES_Encryption.encrypt(ciphertext,atm.sessionKey);
                        atm.sendMSG(ciphertext);
                        atm.uiDashes();
                        System.out.println("Sent Balance Request");
                        atm.uiDashes();
                        incomingMSG = atm.bufferedReader.readLine();
                        ciphertext = AES_Encryption.decrypt(incomingMSG, atm.sessionKey);
                        NonceMessage = receiveNonce(ciphertext);
                        atm.currBalance = NonceMessage[1];
                        atm.uiDashes();
                        System.out.println("Current Balance: $" + atm.currBalance);
                        atm.uiDashes();
                    }
                    case "2","Deposit","Dep","dep" -> {
                        atm.uiDashes();
                        System.out.println("How much are you depositing?\n(This machine does not accept coins)");
                        atm.uiDashes();
                        incomingMSG2 = scanner.nextLine();
                        atm.uiDashes();
                        System.out.println("Depositing: $" + incomingMSG2);
                        atm.uiDashes();
                        genNonce = generateNonce();
                        ciphertext = atm.prepMSG("deposit", genNonce);
                        ciphertext = atm.sessionEncrypt(ciphertext);
                        atm.sendMSG(ciphertext);
                        ciphertext = atm.sessionEncrypt(incomingMSG2);
                        atm.sendMSG(ciphertext);
                        incomingMSG = atm.bufferedReader.readLine();
                        ciphertext = atm.sessionDecrypt(incomingMSG);
                        NonceMessage = receiveNonce(ciphertext);
                        atm.uiDashes();
                        atm.currBalance = NonceMessage[1];
                        System.out.println("Deposit Successful");
                        System.out.println("Current Balance: $" + NonceMessage[1]);
                        atm.uiDashes();
                    }
                    case "3","Withdraw","With","W", "withdraw" -> {
                        atm.uiDashes();
                        System.out.println("How much are you withdrawing?\n(This machine does have change)");
                        atm.uiDashes();
                        incomingMSG2 = scanner.nextLine();
                        if (validWithdraw(atm.currBalance, incomingMSG2)){
                            atm.uiDashes();
                            System.out.println("Withdrawing: $" + incomingMSG2);
                            atm.uiDashes();
                            genNonce = generateNonce();
                            ciphertext = atm.prepMSG("withdraw", genNonce);
                            ciphertext = atm.sessionEncrypt(ciphertext);
                            atm.sendMSG(ciphertext);
                            ciphertext = atm.sessionEncrypt(incomingMSG2);
                            atm.sendMSG(ciphertext);
                            atm.uiDashes();
                            System.out.println("Sent Deposit Request");
                            atm.uiDashes();
                            incomingMSG = atm.bufferedReader.readLine();
                            ciphertext = atm.sessionDecrypt(incomingMSG);
                            NonceMessage = receiveNonce(ciphertext);
                            atm.uiDashes();
                            atm.currBalance = NonceMessage[1];
                            System.out.println("Deposit Successful");
                            System.out.println("Current Balance: $" + NonceMessage[1]);
                            atm.uiDashes();
                        }
                        else{
                            atm.uiDashes();
                            System.out.println("You do not have enough money in your account to do this");
                            atm.uiDashes();
                        }
                    }
                    case "quit", "Quit" -> {
                        atm.uiDashes();
                        System.out.println("Quitting....");
                        atm.uiDashes();
                        atm.closeCon(atm.socket,atm.bufferedReader,atm.bufferedWriter);
                    }
                    default -> {
                        atm.uiDashes();
                    }
                }
            }
        }
    }
}
