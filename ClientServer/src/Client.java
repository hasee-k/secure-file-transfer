import org.mindrot.jbcrypt.BCrypt;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Instant;

public class Client{
    private static PublicKey serverRSAPublicKey;
    private static SecretKey aesKey;
    private static byte[] iv;
    private static Socket socket;
    private static DataOutputStream dataOutputStream;
    private static DataInputStream dataInputStream;
    private static File fileToSend = null;
    private static String loggedInUsername = "";

    public static void main(String[] args) {
        showLoginFrame();
    }

    private static void showLoginFrame() {
        JFrame loginFrame = new JFrame("Login");
        loginFrame.setSize(400, 300);
        loginFrame.setLayout(new BoxLayout(loginFrame.getContentPane(), BoxLayout.Y_AXIS));
        loginFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        loginFrame.setLocationRelativeTo(null);

        JLabel jlTitle = new JLabel("File Sender Login");
        jlTitle.setFont(new Font("Arial", Font.BOLD, 24));
        jlTitle.setBorder(new EmptyBorder(30, 0, 20, 0));
        jlTitle.setAlignmentX(Component.CENTER_ALIGNMENT);

        JPanel jpCredentials = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);

        JLabel jlUsername = new JLabel("Username:");
        jlUsername.setFont(new Font("Arial", Font.PLAIN, 16));
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.EAST;
        jpCredentials.add(jlUsername, gbc);

        JTextField jtfUsername = new JTextField(15);
        jtfUsername.setFont(new Font("Arial", Font.PLAIN, 16));
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        jpCredentials.add(jtfUsername, gbc);

        JLabel jlPassword = new JLabel("Password:");
        jlPassword.setFont(new Font("Arial", Font.PLAIN, 16));
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.anchor = GridBagConstraints.EAST;
        jpCredentials.add(jlPassword, gbc);

        JPasswordField jpfPassword = new JPasswordField(15);
        jpfPassword.setFont(new Font("Arial", Font.PLAIN, 16));
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.anchor = GridBagConstraints.WEST;
        jpCredentials.add(jpfPassword, gbc);

        JPanel jpButton = new JPanel();
        jpButton.setBorder(new EmptyBorder(20, 0, 20, 0));

        JButton jbLogin = new JButton("Login");
        jbLogin.setFont(new Font("Arial", Font.BOLD, 16));
        jbLogin.setPreferredSize(new Dimension(100, 40));
        jpButton.add(jbLogin);

        jbLogin.addActionListener((ActionEvent e) -> {
            String username = jtfUsername.getText().trim();
            String password = new String(jpfPassword.getPassword());

            if (username.isEmpty()) {
                JOptionPane.showMessageDialog(loginFrame, "Please enter a username.", "Username Required", JOptionPane.WARNING_MESSAGE);
                return;
            }

            if (password.isEmpty()) {
                JOptionPane.showMessageDialog(loginFrame, "Please enter a password.", "Password Required", JOptionPane.WARNING_MESSAGE);
                return;
            }

            if (authenticateUser(username, password)) {
                loggedInUsername = username;
                loginFrame.dispose();
                showMainFrame();
            } else {
                JOptionPane.showMessageDialog(loginFrame, "Invalid username or password.", "Login Failed", JOptionPane.ERROR_MESSAGE);
            }

        });

        // Allow Enter key to trigger login
        jpfPassword.addActionListener((ActionEvent e) -> jbLogin.doClick());
        jtfUsername.addActionListener((ActionEvent e) -> jpfPassword.requestFocus());

        loginFrame.add(jlTitle);
        loginFrame.add(jpCredentials);
        loginFrame.add(jpButton);
        loginFrame.setVisible(true);
    }

    private static void showMainFrame() {
        JFrame jFrame = new JFrame("Client - " + loggedInUsername);
        jFrame.setSize(500, 400);
        jFrame.setLayout(new BoxLayout(jFrame.getContentPane(), BoxLayout.Y_AXIS));
        jFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        jFrame.setLocationRelativeTo(null);

        JLabel jlTitle = new JLabel("File Sender");
        jlTitle.setFont(new Font("Arial", Font.BOLD, 20));
        jlTitle.setBorder(new EmptyBorder(20, 0, 10, 0));
        jlTitle.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel jlUser = new JLabel("Logged in as: " + loggedInUsername);
        jlUser.setFont(new Font("Arial", Font.ITALIC, 14));
        jlUser.setBorder(new EmptyBorder(0, 0, 10, 0));
        jlUser.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel jlFileName = new JLabel("No file selected");
        jlFileName.setFont(new Font("Arial", Font.PLAIN, 16));
        jlFileName.setBorder(new EmptyBorder(20, 0, 0, 0));
        jlFileName.setAlignmentX(Component.CENTER_ALIGNMENT);

        JPanel jpButton = new JPanel();
        jpButton.setBorder(new EmptyBorder(50, 0, 10, 0));

        JButton jbSelectFile = new JButton("Select File");
        JButton jbSendFile = new JButton("Send File");
        jbSelectFile.setFont(new Font("Arial", Font.BOLD, 16));
        jbSendFile.setFont(new Font("Arial", Font.BOLD, 16));

        jpButton.add(jbSelectFile);
        jpButton.add(jbSendFile);

        connectToServer();

        jbSelectFile.addActionListener((ActionEvent e) -> {
            JFileChooser jFileChooser = new JFileChooser();
            jFileChooser.setDialogTitle("Select a file to send");
            jFileChooser.setFileFilter(new FileNameExtensionFilter("Text & Image Files", "txt", "png", "jpg", "jpeg"));
            if (jFileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                fileToSend = jFileChooser.getSelectedFile();
                jlFileName.setText("Selected: " + fileToSend.getName());
                System.out.println("File selected: " + fileToSend.getAbsolutePath());
            }
        });

        jbSendFile.addActionListener((ActionEvent e) -> {
            if (fileToSend == null) {
                JOptionPane.showMessageDialog(jFrame, "Please select a file before sending.", "No File Selected", JOptionPane.WARNING_MESSAGE);
                return;
            }
            sendFile(fileToSend);
        });

        jFrame.add(jlTitle);
        jFrame.add(jlUser);
        jFrame.add(jlFileName);
        jFrame.add(jpButton);
        jFrame.setVisible(true);
    }

    private static void connectToServer() {
        try {
            socket = new Socket("localhost", 1234);
            dataOutputStream = new DataOutputStream(socket.getOutputStream());
            dataInputStream = new DataInputStream(socket.getInputStream());

            // Receive RSA Public Key
            int publicKeyLength = dataInputStream.readInt();
            byte[] publicKeyBytes = new byte[publicKeyLength];
            dataInputStream.readFully(publicKeyBytes);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            serverRSAPublicKey = keyFactory.generatePublic(publicKeySpec);
            System.out.println("Received RSA Public Key from server.");

            // Generate AES Key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            aesKey = keyGen.generateKey();
            System.out.println("Generated AES Key.");

            // Encrypt AES Key with RSA Public Key
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverRSAPublicKey);
            byte[] encryptedAESKey = rsaCipher.doFinal(aesKey.getEncoded());

            // Generate IV
            iv = new byte[16];
            new SecureRandom().nextBytes(iv);

            // Send encrypted AES Key and IV
            dataOutputStream.writeInt(encryptedAESKey.length);
            dataOutputStream.write(encryptedAESKey);

            dataOutputStream.writeInt(iv.length);
            dataOutputStream.write(iv);

            System.out.println("Sent AES Key and IV to server.");

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Failed to connect to server or exchange keys.");
            System.exit(1);
        }
    }

    private static void sendFile(File file) {
        try {
            long timestamp = Instant.now().toEpochMilli();
            // Convert timestamp to bytes
            byte[] timestampBytes = ByteBuffer.allocate(8).putLong(timestamp).array();

            // Read file bytes
            FileInputStream fis = new FileInputStream(file);
            byte[] fileBytes = fis.readAllBytes();
            fis.close();

            // Hash file before encryption using SHA-256 (or SHA-512) with key appended
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(fileBytes); // M (message/file)
            digest.update(timestampBytes); // T (timestamp)
            digest.update(loggedInUsername.getBytes());
            digest.update(aesKey.getEncoded()); // K (key)
            byte[] hashOfFile = digest.digest();

            // Encrypt file with AES
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
            byte[] encryptedFileBytes = aesCipher.doFinal(fileBytes);

            // Send username (now using the logged-in username)
            byte[] userNameBytes = loggedInUsername.getBytes();
            dataOutputStream.writeInt(userNameBytes.length);
            dataOutputStream.write(userNameBytes);
            System.out.println("Sent username: " + loggedInUsername);

            // Send file name
            byte[] fileNameBytes = file.getName().getBytes();
            dataOutputStream.writeInt(fileNameBytes.length);
            dataOutputStream.write(fileNameBytes);


            // Send timestamp
            dataOutputStream.writeLong(timestamp);
            System.out.println("Sent timestamp: " + timestamp + " (" + Instant.ofEpochMilli(timestamp) + ")");

            // Send encrypted file
            dataOutputStream.writeInt(encryptedFileBytes.length);
            dataOutputStream.write(encryptedFileBytes);
            System.out.println("Sent file: " + file.getName() + " (Encrypted with AES)");

            // Send hash length and hash
            dataOutputStream.writeInt(hashOfFile.length);
            dataOutputStream.write(hashOfFile);
            System.out.println("Sent hash of file with key appended");


        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Failed to send file.");
        }
    }

    private static boolean authenticateUser(String username, String password) {
        String url = System.getenv("DB_URL");
        String user = System.getenv("DB_USER");
        String dbPassword = System.getenv("DB_PASSWORD");

        try (Connection conn = DriverManager.getConnection(url, user, dbPassword)) {
            String sql = "SELECT password_hash FROM users WHERE username = ?";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                String storedHash = rs.getString("password_hash");
                return BCrypt.checkpw(password, storedHash);
            } else {
                System.out.println("User not found.");
                return false;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

}