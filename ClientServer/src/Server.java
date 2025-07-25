import java.awt.Component;
import java.awt.Font;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import javax.swing.*;
import javax.swing.border.EmptyBorder;

public class Server {
    static ArrayList<MyFile> myFiles = new ArrayList<>();
    static KeyPair rsaKeyPair;

    public static void main(String[] args) throws IOException {
        // Generate RSA key pair for key exchange
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            rsaKeyPair = keyPairGenerator.generateKeyPair();
            System.out.println("RSA Key pair generated for key exchange");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return;
        }

        int fileId = 0;
        JFrame jFrame = new JFrame("Server");
        jFrame.setSize(400, 400);
        jFrame.setLayout(new BoxLayout(jFrame.getContentPane(), BoxLayout.Y_AXIS));
        jFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JPanel jPanel = new JPanel();
        jPanel.setLayout(new BoxLayout(jPanel, BoxLayout.Y_AXIS));
        JScrollPane jScrollPane = new JScrollPane(jPanel);
        jScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

        JLabel jlTitle = new JLabel("File Receiver (RSA+AES Encrypted)");
        jlTitle.setFont(new Font("Arial", Font.BOLD, 25));
        jlTitle.setBorder(new EmptyBorder(20, 0, 10, 0));
        jlTitle.setAlignmentX(Component.CENTER_ALIGNMENT);

        jFrame.add(jlTitle);
        jFrame.add(jScrollPane);
        jFrame.setVisible(true);

        ServerSocket serverSocket = new ServerSocket(1234);
        try {
            while (true) {
                Socket socket = serverSocket.accept();
                DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
                DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

                // Send RSA public key to client for key exchange
                byte[] publicKeyBytes = rsaKeyPair.getPublic().getEncoded();
                dataOutputStream.writeInt(publicKeyBytes.length);
                dataOutputStream.write(publicKeyBytes);
                dataOutputStream.flush();
                System.out.println("RSA public key sent to client");

                Thread t = new ClientHandler(socket, dataInputStream, myFiles, jPanel, rsaKeyPair.getPrivate());
                t.start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (serverSocket != null) {
                try {
                    serverSocket.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }
}