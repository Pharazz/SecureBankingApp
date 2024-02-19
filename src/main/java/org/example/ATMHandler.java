package org.example;

import java.io.*;
import java.net.Socket;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
//import java.util.logging.LogManager;
//import java.util.logging.Logger;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

public class ATMHandler implements Runnable{

    public static ArrayList<ATMHandler> atmHandlers = new ArrayList<>();
    private static Set<byte[]> usedNonces = new HashSet<>();
    private static final Logger logger = LogManager.getLogger(ATMHandler.class.getName());
    public static RSA rsa = new RSA();
    private static AES_Encryption aes = new AES_Encryption();
    private String fileEncryptionKey;
    private String sessionKey;
    private Socket socket;
    private PublicKey atmPub;
    private BufferedReader bufferedReader;
    private BufferedWriter bufferedWriter;
//    private PrintWriter out;
    private String clientUsername;
    private String clientPassword;
    private String clientAccNum;

    public ATMHandler(Socket socket){
        try {
            this.socket = socket;
            this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
//            this.out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
            this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            this.clientUsername = bufferedReader.readLine();
            atmHandlers.add(this); //Might not need this
            this.fileEncryptionKey = AES_Encryption.generateKey("FILEKEY");
            //broadcastMessage("SERVER: " + this.clientUsername + " has begun banking");
        } catch (IOException | NoSuchAlgorithmException e) {
            closeCon(socket, bufferedReader, bufferedWriter);
        }
    }

    @Override
    public void run(){
        String messageFromATM;
        String accountBal;
        String[] ciphertext = new String[2];
        String sendingCipher;
        byte[] nxtNonce;
        while (socket.isConnected()){
            //Handling code goes here
            try{
                this.exchangePublicKeys();//Step 1 Exchange Public Keys
                messageFromATM = this.authenticateATM();//Nonce to use next
                //idk
                messageFromATM = this.authenticateClient();//AuthenticateClient and get AccountNumber
                accountBal = this.openAccountFile(this.clientAccNum);//Generate and distribute session key
                this.makeSessionKey();//generate sessionkey and save it
                this.sendSessionKey(messageFromATM);//Send sessionkey and nonce
            } catch (Exception e){
                e.printStackTrace();
                closeCon(this.socket, this.bufferedReader, this.bufferedWriter);
                break;
            }
            while(socket.isConnected()){//Authentication Complete now conduct banking
                try {
                    messageFromATM = bufferedReader.readLine();//get request from ATM
                    //Get Decrypted Nonce and Message out of Communication
                    ciphertext = receiveNonce(AES_Encryption.decrypt(messageFromATM, this.sessionKey));
                    switch (ciphertext[1]) {
                        case "getBal", "getBalance", "Balance" -> {
                            nxtNonce = generateNonce();
                            accountBal = this.openAccountFile(this.clientAccNum);
                            System.out.println("Bal: " + accountBal);
                            sendingCipher = prepMSG(accountBal, nxtNonce);
                            sendingCipher = sessionEncrypt(sendingCipher);
                            System.out.println("Sending: " + sendingCipher);
                            logger.info("Balance requested and sent");
                            logger.info(encInfo("Balance requested and sent"));
                            sendMSG(sendingCipher);
                        }
                        case "deposit", "Deposit" ,"dep", "depo" -> {
                            messageFromATM = bufferedReader.readLine();
                            messageFromATM = sessionDecrypt(messageFromATM);
                            nxtNonce = generateNonce();
                            System.out.println("Deposit Request: "+messageFromATM);
                            logger.info("Deposit: Requested");
                            logger.info(encInfo("Deposit: Reguested"));
                            sendingCipher = this.writeToAccountFile(this.clientAccNum, messageFromATM, "Deposit");
                            sendingCipher = prepMSG(sendingCipher, nxtNonce);
                            sendingCipher = sessionEncrypt(sendingCipher);
                            System.out.println("Sending: " + sendingCipher);
                            logger.info("Account Deposit: "+ messageFromATM);
                            logger.info(encInfo("Account Deposit: "+ messageFromATM));
                            sendMSG(sendingCipher);
                        }
                        case "withdrew", "withdraw" ,"take", "remove" -> {
                            messageFromATM = bufferedReader.readLine();
                            messageFromATM = sessionDecrypt(messageFromATM);
                            nxtNonce = generateNonce();
                            System.out.println("Withdrawl Request: "+ messageFromATM);
                            logger.info("Withdrawal: Requested");
                            logger.info(encInfo("Withdrawal: Requested"));
                            sendingCipher = this.writeToAccountFile(this.clientAccNum, messageFromATM, "Withdraw");
                            sendingCipher = prepMSG(sendingCipher, nxtNonce);
                            sendingCipher = sessionEncrypt(sendingCipher);
                            System.out.println("Sending: " + sendingCipher);
                            logger.info("Account Withdrawal: "+ messageFromATM);
                            logger.info(encInfo("Account Withdrawal: "+ messageFromATM));
                            sendMSG(sendingCipher);
                        }
                        default -> {
                        }
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }
    }



    public void exchangePublicKeys() throws Exception {
        logger.info("Beginning Public Key Exchange");
        logger.info(encInfo("Beginning Public Key Exchange"));
        String keyStr = RSA.StringfromKey(rsa.publicKey); //Public Key into String
        this.sendMSG(keyStr);//Send Public Key as String
        System.out.println("Sent Key: " + keyStr);
        logger.info("Sent PublicKey to ATM" );
        logger.info(encInfo("Sent PublicKey to ATM" ));
        keyStr = this.bufferedReader.readLine();
        System.out.println("Received Key: " + keyStr);
        logger.info("Received Public Key from ATM");
        logger.info(encInfo("Received Public Key from ATM"));
        this.atmPub =  rsa.KeyfromString(keyStr);
        return;
    }

    public void makeSessionKey() throws NoSuchAlgorithmException {
        String seed = AES_Encryption.generateRandomString(10);//generate random string
        this.sessionKey = AES_Encryption.generateKey(seed);// get AES key
    }

    public void sendSessionKey(String Nonce) throws Exception {
        String Cipher1 = prepMSG(this.sessionKey, hexToBytes(Nonce));//Attach Nonce from ATM to message1 with Key
        String Cipher2 = this.clientAccNum;// Encrypt with session key
        Cipher1 = rsa.encrypt(Cipher1, this.atmPub);//encrypt Message1 with Public Key of ATM
        Cipher2 = AES_Encryption.encrypt(Cipher2, this.sessionKey);//Encrypt account Number with session key
        this.sendMSG(Cipher1);//Send Session Key
        this.sendMSG(Cipher2);//Send AccNumber Encrypted w/ Session Key

    }

    public String sessionEncrypt(String content) throws Exception {
        return AES_Encryption.encrypt(content, this.sessionKey);
    }

    public String sessionDecrypt(String cipher) throws Exception {
        return AES_Encryption.decrypt(cipher, this.sessionKey);
    }

    public String encInfo(String content) throws Exception {
        return AES_Encryption.encrypt(content, this.fileEncryptionKey);
    }

    public String decryptFileContent(String content) throws Exception {
        return AES_Encryption.decrypt(content, this.fileEncryptionKey);
    }

    public String openAccountFile(String AccountNum) throws Exception {
        String AccountBalance;
        String fileName = System.getProperty("user.dir") + "/Accounts/" +AccountNum + ".txt";
        try {
            File file = new File(fileName);//Open file
            BufferedReader br = new BufferedReader(new FileReader(file));//Cast as Br
            AccountBalance = br.readLine();//Read
            br.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return decryptFileContent(AccountBalance);
    }

    public String writeToAccountFile(String AccountNum, String value, String action) throws Exception {
        String AccountBalance;
        String fileName = System.getProperty("user.dir") + "/Accounts/" +AccountNum + ".txt";
        try {
            File file = new File(fileName);//Open file
            BufferedReader br = new BufferedReader(new FileReader(file));//Cast as Br
            AccountBalance = br.readLine();//Read
            br.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        AccountBalance = decryptFileContent(AccountBalance);
        if (action.equals("Deposit")){
            AccountBalance = addStrings(AccountBalance, value);
        } else if (action.equals("Withdraw")) {
            AccountBalance = subStrings(AccountBalance, value);
        }
        try {
            File file2 = new File(fileName);//Open file
            BufferedWriter wr = new BufferedWriter(new FileWriter(file2, false));//Cast as Br
            AccountBalance = AES_Encryption.encrypt(AccountBalance, this.fileEncryptionKey);
            wr.write(AccountBalance);//Read
            wr.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return decryptFileContent(AccountBalance);
    }
    public static String addStrings(String num1, String num2) {
        int n1 = Integer.parseInt(num1);
        int n2 = Integer.parseInt(num2);
        int sum = n1 + n2;
        String result = Integer.toString(sum);
        return result;
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


    public String authenticateATM() throws Exception {
        //Receive ATM ID unencrypted (Initiation)
        logger.info("Beginning ATM Authentication");
        logger.info(encInfo("Beginning ATM Authentication"));
        String ATMID = this.bufferedReader.readLine();
        System.out.println("ATM ID: " + ATMID);
        logger.info("Received ATM ID");
        logger.info(encInfo("Received ATM ID"));
        //Verify ATM-ID
        //...
        //Verify ATM-ID
        //Encrypt Server ID using Public Key
        String ServerID = "Server1";
        byte[] NonceA = generateNonce();//Make Nonce A
        String MessageString = prepMSG(ServerID, NonceA);//Make Message String
        System.out.println("Attached Nonce: "+ MessageString);
        String CipherText = rsa.encrypt(MessageString, this.atmPub);//Encrypt Message using Alternate Public Key
        System.out.println("CipherText: " + CipherText);
        this.sendMSG(CipherText);// Send CipherText to ATM
        CipherText = this.bufferedReader.readLine();//receive Ciphertext NonceA and Nonce for Next Communication
        MessageString = rsa.decrypt(CipherText, rsa.privateKey);// Decrypt Using Private Key
        String[] NonceMessage = new String[2];
        NonceMessage = receiveNonce(MessageString);//Extract Nonce and Message by casting input as byte
        System.out.println("Nonce: " + NonceMessage[0] +"\nMessage: " + NonceMessage[1]);
        logger.info("Received Message and Nonce");
        logger.info(encInfo("Received Message and Nonce"));
        logger.info(encInfo("Nonce: " + NonceMessage[0] +"\nMessage: " + NonceMessage[1]));
        if(isEqualNonce(NonceA, hexToBytes(NonceMessage[0])) && isValidNonce(hexToBytes(NonceMessage[1]))){
            System.out.println("Nonce Verified, ATM is authentic");
            logger.info(encInfo("Nonce Verified"));
        }
        else{
            logger.error("Nonce does not match error");
            System.out.println("Error Nonce does not match");
            System.out.println("Nonce 1:"+ bytesToHex(NonceA));
            System.out.println("Nonce 2:"+ NonceMessage[0]);
            System.out.println("Newest Nonce:"+ NonceMessage[1]);
        }
        return NonceMessage[1];
    }

    private String authenticateClient() throws Exception {
        //Listen for 2 messages
        String Cipher1 = this.bufferedReader.readLine();//NonceA|Username
        String Cipher2 = this.bufferedReader.readLine();//PasswordHash
        String MessageString1 = rsa.decrypt(Cipher1, rsa.privateKey);//Decrypt Nonce and Username
        String MessageString2 = rsa.decrypt(Cipher2, rsa.privateKey);//Decrypt Nonce and Username
        String[] NonceMessage = new String[2];
        NonceMessage = receiveNonce(MessageString1);//Separate Nonce and Message
        if (checkClientValidity(NonceMessage[1], MessageString2)){
            logger.info("Valid Connection from Client");
            logger.info(encInfo("Valid Connection from Client"));
            System.out.println("Valid Connection from client");
            //should have account number now in object so generate sessionKey
        }
        else{
            logger.error("Failed to Verify Client Info");
            System.out.println("Failed to Verify Client");
            closeCon(this.socket, this.bufferedReader, this.bufferedWriter);
        }
        return NonceMessage[0];

    }
    public boolean checkClientValidity(String clientUsername, String clientPassword){
        boolean verdict = false;//By default its false
        String userHash, passHash;
        String fileName = System.getProperty("user.dir") + "/Clientele/" +clientUsername + ".txt";
        try {
            //Get Hashes for username and password
            userHash = AES_Encryption.encrypt(clientUsername, this.fileEncryptionKey);
            passHash = AES_Encryption.encrypt(clientPassword, this.fileEncryptionKey);
            File file = new File(fileName);//Open file
            BufferedReader br = new BufferedReader(new FileReader(file));//Cast as Br

            String name = br.readLine();//Get namehash
            String passwordHash = br.readLine();//Get passwordHash
            String accountNumber = br.readLine();//Get accountNumberHash

            System.out.println("Name: " + name);
            System.out.println("Password hash: " + passwordHash);
            System.out.println("Account number: " + accountNumber);

            if (name.equals(userHash) && passwordHash.equals(passHash)) {
                logger.info("Customer Account Details Valid");// customer account details are valid
                logger.info(encInfo("Customer Account Details Valid"));// customer account details are valid
                this.clientAccNum = AES_Encryption.decrypt(accountNumber,this.fileEncryptionKey);
                verdict = true;
            } else {
                logger.error("Invalid Account Details");
                // customer account details are invalid
            }
            br.close();
        } catch (FileNotFoundException e) {
            System.out.println("File not found: " + fileName);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return verdict;
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
        System.out.println("Generated:" + Base64.getEncoder().encodeToString(nonce));
        System.out.println(Base64.getEncoder().encodeToString(nonce).length());
        System.out.println(bytesToHex(nonce));
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
    public void sendMSG(String msg) throws IOException {
        this.bufferedWriter.write(msg);
        this.bufferedWriter.newLine();
        this.bufferedWriter.flush();
        return;
    }

    public void removeATMHandler(){
        atmHandlers.remove(this);
    }

    public void closeCon(Socket socket, BufferedReader bufferedReader, BufferedWriter bufferedWriter){
        removeATMHandler();
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
}

