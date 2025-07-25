import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.ArrayList;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.*;
import javax.swing.border.EmptyBorder;

public class ClientHandler extends Thread {
    private Socket socket;
    private DataInputStream dataInputStream;
    private PrivateKey rsaPrivateKey;
    static ArrayList<MyFile> myFiles = new ArrayList<>();
    int fileId = 0;
    JPanel jPanel = new JPanel();

    public ClientHandler(Socket socket, DataInputStream dataInputStream, ArrayList<MyFile> myFiles, JPanel jPanel, PrivateKey rsaPrivateKey) {
        this.socket = socket;
        this.dataInputStream = dataInputStream;
        this.myFiles = myFiles;
        this.jPanel = jPanel;
        this.rsaPrivateKey = rsaPrivateKey;
    }

    @Override
    public void run() {
        try {
            // First, receive the encrypted AES key from client
            int encryptedKeyLength = dataInputStream.readInt();
            byte[] encryptedAESKey = new byte[encryptedKeyLength];
            dataInputStream.readFully(encryptedAESKey);

            // Decrypt AES key using RSA private key
            SecretKeySpec aesKey = decryptAESKey(encryptedAESKey);
            if (aesKey == null) {
                System.err.println("Failed to decrypt AES key");
                return;
            }
            System.out.println("AES key received and decrypted successfully");

            // Receive IV for AES decryption
            int ivLength = dataInputStream.readInt();
            byte[] iv = new byte[ivLength];
            dataInputStream.readFully(iv);
            System.out.println("IV received");



            // Read user name
            int userNameLength = dataInputStream.readInt();
            byte[] userNameBytes = new byte[userNameLength];
            dataInputStream.readFully(userNameBytes, 0, userNameBytes.length);
            String userName = new String(userNameBytes);
            System.out.println("username received "+ userName);

            // Read file name
            int fileNameLength = dataInputStream.readInt();
            System.out.println("received file name sent, length = " + fileNameLength);
            if (fileNameLength > 0) {




                byte[] fileNameBytes = new byte[fileNameLength];
                dataInputStream.readFully(fileNameBytes, 0, fileNameBytes.length);
                String fileName = new String(fileNameBytes);
                System.out.println("received file name = " + fileName);

                long timestamp = dataInputStream.readLong();
                System.out.println("file is sent at = " + timestamp);

                // Read encrypted file content
                int fileContentLength = dataInputStream.readInt();

                System.out.println("received file bytes sent, length = " + fileContentLength);

                if (fileContentLength > 0) {
                    byte[] encryptedFileBytes = new byte[fileContentLength];
                    dataInputStream.readFully(encryptedFileBytes, 0, fileContentLength);

                    // Decrypt the file content using AES
                    byte[] decryptedFileBytes = decryptFileWithAES(encryptedFileBytes, aesKey, iv);

                    if (decryptedFileBytes != null) {
                        long currentTime = Instant.now().toEpochMilli();
                        if (currentTime - timestamp < 300000) {

                            System.out.println("Message was sent less than 5 minutes ago");

                            JPanel jpFileRow = new JPanel();
                            jpFileRow.setLayout(new BoxLayout(jpFileRow, BoxLayout.Y_AXIS));

                            JLabel jFileName = new JLabel(userName + " sends " + fileName + " (AES Encrypted)");
                            jFileName.setFont(new Font("Arial", Font.BOLD, 20));
                            jFileName.setBorder(new EmptyBorder(10, 0, 10, 0));
                            jFileName.setAlignmentX(Component.CENTER_ALIGNMENT);

                            jpFileRow.setName(String.valueOf(fileId));

                            for (MouseListener ml : jpFileRow.getMouseListeners()) {
                                jpFileRow.removeMouseListener(ml);
                            }
                            jpFileRow.addMouseListener(getMyMouseListener());

                            jpFileRow.add(jFileName);

                            jPanel.add(jpFileRow);
                            jPanel.revalidate();
                            jPanel.repaint();

                            jPanel.add(jpFileRow);
                            jpFileRow.validate();

                            myFiles.add(new MyFile(fileId, fileName, decryptedFileBytes, getFileExtension(fileName)));
                            fileId++;

                            System.out.println("File '" + fileName + "' received and decrypted successfully");
                            System.out.println("Decrypted file length: " + decryptedFileBytes.length);


                        }
                        else {
                            System.out.println("Message is too old ");
                        }


                        // Receive hash
                        int hashLength = dataInputStream.readInt();
                        byte[] receivedHash = new byte[hashLength];
                        dataInputStream.readFully(receivedHash);
                        System.out.println("Received hash of file with key appended");

// Compute hash on server side
                        MessageDigest digest = MessageDigest.getInstance("SHA-256");
                        digest.update(decryptedFileBytes); // M'
                        digest.update(ByteBuffer.allocate(8).putLong(timestamp).array());
                        digest.update(aesKey.getEncoded()); // K
                        byte[] computedHash = digest.digest();




// Verify integrity
                        if (MessageDigest.isEqual(receivedHash, computedHash)) {
                            System.out.println("Integrity verified: hash matches.");
                        } else {
                            System.err.println("Integrity check failed: hash does not match.");

                        }



                    } else {
                        System.err.println("Failed to decrypt file: " + fileName);
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private SecretKeySpec decryptAESKey(byte[] encryptedAESKey) {
        try {
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
            byte[] decryptedKey = rsaCipher.doFinal(encryptedAESKey);
            return new SecretKeySpec(decryptedKey, "AES");
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private byte[] decryptFileWithAES(byte[] encryptedData, SecretKeySpec aesKey, byte[] iv) {
        try {
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
            return aesCipher.doFinal(encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static MouseListener getMyMouseListener() {
        return new MouseListener() {

            @Override
            public void mouseClicked(MouseEvent e) {
                JPanel jPanel = (JPanel) e.getSource();
                int fileId = Integer.parseInt(jPanel.getName());

                for(MyFile myFile: myFiles) {
                    if(myFile.getId() == fileId) {
                        JFrame jfPreview = createFrame(myFile.getName(), myFile.getData(), myFile.getFileExtension());
                        jfPreview.setVisible(true);
                    }
                }
            }


            @Override
            public void mousePressed(MouseEvent e) {}

            @Override
            public void mouseReleased(MouseEvent e) {}

            @Override
            public void mouseEntered(MouseEvent e) {}

            @Override
            public void mouseExited(MouseEvent e) {}
        };
    }

    public static JFrame createFrame(String fileName, byte[] fileData, String fileExtension) {
        JFrame jFrame = new JFrame ("File Downloader");
        jFrame.setSize(400,400);

        JPanel jPanel = new JPanel();
        jPanel.setLayout(new BoxLayout(jPanel,BoxLayout.Y_AXIS));

        JLabel jlTitle = new JLabel("File Downloader");
        jlTitle.setFont(new Font("Arial", Font.BOLD, 25));
        jlTitle.setBorder(new EmptyBorder(20, 0, 10, 0));
        jlTitle.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel jlPrompt = new JLabel("Are you sure you want to download " + fileName);
        jlPrompt.setFont(new Font("Arial", Font.BOLD, 20));
        jlPrompt.setBorder(new EmptyBorder(20, 0, 10, 0));
        jlPrompt.setAlignmentX(Component.CENTER_ALIGNMENT);

        JButton jbYes = new JButton("Yes");
        jbYes.setPreferredSize(new Dimension(150,75));
        jbYes.setFont(new Font("Arial", Font.BOLD, 20));

        JButton jbNo = new JButton("No");
        jbNo.setPreferredSize(new Dimension(150,75));
        jbNo.setFont(new Font("Arial", Font.BOLD, 20));

        JLabel jlFileContent = new JLabel();
        jlFileContent.setAlignmentX(Component.CENTER_ALIGNMENT);

        JPanel jpButtons = new JPanel();
        jpButtons.setBorder(new EmptyBorder(20, 0, 10, 0));
        jpButtons.add(jbYes);
        jpButtons.add(jbNo);

        if(fileExtension.equalsIgnoreCase("txt")) {
            jlFileContent.setText("<html>" + new String(fileData) + "</html>");
        } else {
            jlFileContent.setIcon(new ImageIcon(fileData));
        }

        jbYes.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                File fileToDownload = new File(fileName);
                try {
                    FileOutputStream fileOutputStream = new FileOutputStream(fileToDownload);
                    fileOutputStream.write(fileData);
                    fileOutputStream.close();
                    jFrame.dispose();
                } catch (IOException error) {
                    error.printStackTrace();
                }
            }
        });

        jbNo.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                jFrame.dispose();
            }
        });

        jPanel.add(jlTitle);
        jPanel.add(jlPrompt);
        jPanel.add(jlFileContent);
        jPanel.add(jpButtons);

        jFrame.add(jPanel);

        return jFrame;
    }

    public static String getFileExtension(String fileName) {
        int i = fileName.lastIndexOf('.');
        if (i > 0) {
            return fileName.substring(i + 1);
        } else {
            return "No extension Found";
        }
    }
}