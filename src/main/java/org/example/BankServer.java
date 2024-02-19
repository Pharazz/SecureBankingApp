package org.example;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.*;

public class BankServer {
    private ServerSocket serverSocket;

    public BankServer(ServerSocket serverSocket){
        this.serverSocket = serverSocket;
    }

    public void startServer(){
        try{
            while(!serverSocket.isClosed()){
                Socket socket = serverSocket.accept();
                System.out.println("New request from ATM");
                ATMHandler atmHandler = new ATMHandler(socket);

                Thread thread = new Thread(atmHandler);
                thread.start();
            }
        } catch (IOException e){

        }
    }

    public void closeServerSocket() {
        try {
            if (serverSocket != null){
                serverSocket.close();
            }
        } catch (IOException e){
            e.printStackTrace();
        }
    }

    public static void main (String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(1234);
        BankServer server = new BankServer(serverSocket);
        server.startServer();
    }
}
