
import java.io.*;
import java.net.*;
import java.security.*;
import javax.swing.JOptionPane;
import java.math.*;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class PasswordScreen extends javax.swing.JFrame {

    public PasswordScreen() {
        initComponents();
    }

    String CharacterRead;
    //string for random password generator
    private static SecureRandom random = new SecureRandom();
    private static final String Caps = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String NonCaps = "abcdefghijklmnopqrstuvwxyz";
    private static final String Numbers = "0123456789";
    private static final String Symbols = "!@#$%^&*_=+-/";

    //Encryption Variables
    private static SecretKeySpec secretKey;
    private static byte[] key;

    //Hashing algorithm 
    private static String PasswordHasher(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        int iterations = 1000;
        char[] chars = password.toCharArray();
        byte[] salt = {(byte) 0xba, (byte) 0x8a, 0x0d, 0x45, (byte) 0xad, (byte) 0xd0, 0x11, (byte) 0x98, (byte) 0xa8, 0x08, 0x1b, 0x11, 0x03};

        PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 64 * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        byte[] hash = skf.generateSecret(spec).getEncoded();
        return toHex(hash);
    }

    private static String toHex(byte[] array) throws NoSuchAlgorithmException {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if (paddingLength > 0) {
            return String.format("%0" + paddingLength + "d", 0) + hex;
        } else {
            return hex;
        }
    }

    //Encryption algorithm 
    public static void setKey(String myKey) {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public static String encrypt(String strToEncrypt, String secret) {
        try {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } catch (UnsupportedEncodingException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    //Generating random passwords
    public static String generatePassword(int CharacterRead, String dic) {
        String result = "";
        for (int i = 0; i < CharacterRead; i++) {
            int index = random.nextInt(dic.length());
            result += dic.charAt(index);
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel2 = new javax.swing.JLabel();
        jPanel1 = new javax.swing.JPanel();
        Title = new javax.swing.JLabel();
        jLabel1 = new javax.swing.JLabel();
        jTextField1 = new javax.swing.JTextField();
        jButton1 = new javax.swing.JButton();
        numCheck = new javax.swing.JCheckBox();
        symbCheck = new javax.swing.JCheckBox();
        lwrcaseCheck = new javax.swing.JCheckBox();
        upcaseCheck = new javax.swing.JCheckBox();
        jLabel3 = new javax.swing.JLabel();
        charEnter = new javax.swing.JTextField();
        Randpassfield = new javax.swing.JTextField();
        GenerBtn = new javax.swing.JButton();
        exit = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setBackground(new java.awt.Color(255, 255, 255));
        setPreferredSize(new java.awt.Dimension(303, 346));
        setResizable(false);

        jPanel1.setBackground(new java.awt.Color(255, 255, 255));
        jPanel1.setForeground(new java.awt.Color(255, 255, 255));
        jPanel1.setPreferredSize(new java.awt.Dimension(303, 356));

        Title.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        Title.setText("Password Analyzer");

        jLabel1.setText("Enter Password:");

        jTextField1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextField1ActionPerformed(evt);
            }
        });

        jButton1.setBackground(new java.awt.Color(255, 255, 255));
        jButton1.setText("Check");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        numCheck.setBackground(new java.awt.Color(255, 255, 255));
        numCheck.setText("Numbers");
        numCheck.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                numCheckActionPerformed(evt);
            }
        });

        symbCheck.setBackground(new java.awt.Color(255, 255, 255));
        symbCheck.setText("Symbols");

        lwrcaseCheck.setBackground(new java.awt.Color(255, 255, 255));
        lwrcaseCheck.setText("Lowercase");
        lwrcaseCheck.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                lwrcaseCheckActionPerformed(evt);
            }
        });

        upcaseCheck.setBackground(new java.awt.Color(255, 255, 255));
        upcaseCheck.setText("Uppercase");
        upcaseCheck.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                upcaseCheckActionPerformed(evt);
            }
        });

        jLabel3.setText("Enter Password Length");

        charEnter.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                charEnterActionPerformed(evt);
            }
        });

        Randpassfield.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                RandpassfieldActionPerformed(evt);
            }
        });

        GenerBtn.setBackground(new java.awt.Color(255, 255, 255));
        GenerBtn.setText("Generate");
        GenerBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                GenerBtnActionPerformed(evt);
            }
        });

        exit.setBackground(new java.awt.Color(255, 255, 255));
        exit.setText("Exit");
        exit.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                exitActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                                .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, 144, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addComponent(charEnter, javax.swing.GroupLayout.PREFERRED_SIZE, 51, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addContainerGap())
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                                .addComponent(Title, javax.swing.GroupLayout.PREFERRED_SIZE, 162, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(91, 91, 91))))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(exit, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addComponent(jLabel1)
                                .addGap(0, 0, Short.MAX_VALUE))
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                                .addComponent(Randpassfield)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(GenerBtn)))
                        .addContainerGap())
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addComponent(jTextField1, javax.swing.GroupLayout.PREFERRED_SIZE, 217, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(jButton1))
                            .addComponent(numCheck)
                            .addComponent(symbCheck)
                            .addComponent(upcaseCheck)
                            .addComponent(lwrcaseCheck))
                        .addGap(0, 1, Short.MAX_VALUE))))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(Title, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jTextField1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButton1))
                .addGap(33, 33, 33)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3)
                    .addComponent(charEnter, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(24, 24, 24)
                .addComponent(lwrcaseCheck)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(upcaseCheck)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(numCheck)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(symbCheck)
                .addGap(18, 18, 18)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(Randpassfield, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(GenerBtn))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(exit)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(271, Short.MAX_VALUE)
                .addComponent(jLabel2)
                .addGap(32, 32, 32))
            .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, 319, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(46, 46, 46)
                .addComponent(jLabel2)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        setSize(new java.awt.Dimension(319, 386));
        setLocationRelativeTo(null);
    }// </editor-fold>//GEN-END:initComponents

    private void jTextField1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextField1ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jTextField1ActionPerformed

    @SuppressWarnings("empty-statement")
    private void GenerBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_GenerBtnActionPerformed

        //reading characters from field
        int CharacterRead;
        try {
            if (charEnter.getText().equals("")) {
                JOptionPane.showMessageDialog(exit, "Value Must be Entered");
            } else {

                CharacterRead = Integer.parseInt(charEnter.getText());

                if (CharacterRead < 8 || CharacterRead > 32) {
                    JOptionPane.showMessageDialog(exit, "Enter Password Length must be set to between 8-32");
                } else {

                    //checking password length
                    if (CharacterRead > 7 && CharacterRead < 31) {
                        //System.out.println("There are this many characters " + CharacterRead + "\n");

                        boolean case1, case2, case3, case4;
                        case1 = lwrcaseCheck.isSelected();
                        case2 = upcaseCheck.isSelected();
                        case3 = numCheck.isSelected();
                        case4 = symbCheck.isSelected();

                        if (case1 && case2 && case3 && case4) {
                            String password = generatePassword(CharacterRead, NonCaps + Caps + Numbers + Symbols);
                            Randpassfield.setText(password);
                        }

                        if (!case1 && case2 && !case3 && !case4) {
                            String password = generatePassword(CharacterRead, Caps);
                            Randpassfield.setText(password);
                        }

                        if (!case1 && case2 && case3 && case4) {
                            String password = generatePassword(CharacterRead, Caps + Numbers + Symbols);
                            Randpassfield.setText(password);
                        }

                        if (!case1 && !case2 && case3 && case4) {
                            String password = generatePassword(CharacterRead, Numbers + Symbols);
                            Randpassfield.setText(password);
                        }

                        if (!case1 && !case2 && !case3 && case4) {
                            String password = generatePassword(CharacterRead, Symbols);
                            Randpassfield.setText(password);
                        }

                        if (case1 && !case2 && !case3 && !case4) {
                            String password = generatePassword(CharacterRead, NonCaps);
                            Randpassfield.setText(password);
                        }

                        if (case1 && case2 && !case3 && !case4) {
                            String password = generatePassword(CharacterRead, NonCaps + Caps);
                            Randpassfield.setText(password);
                        }

                        if (case1 && case2 && case3 && !case4) {
                            String password = generatePassword(CharacterRead, NonCaps + Caps + Numbers);
                            Randpassfield.setText(password);
                        }

                        if (case1 && !case2 && !case3 && case4) {
                            String password = generatePassword(CharacterRead, NonCaps + Symbols);
                            Randpassfield.setText(password);
                        }

                        if (!case1 && case2 && case3 && !case4) {
                            String password = generatePassword(CharacterRead, Caps + Numbers);
                            Randpassfield.setText(password);
                        }

                        if (!case1 && !case2 && case3 && !case4) {
                            String password = generatePassword(CharacterRead, Numbers);
                            Randpassfield.setText(password);
                        }

                        if (case1 && !case2 && case3 && case4) {
                            String password = generatePassword(CharacterRead, NonCaps + Numbers + Symbols);
                            Randpassfield.setText(password);
                        }

                        if (case1 && case2 && !case3 && case4) {
                            String password = generatePassword(CharacterRead, NonCaps + Caps + Symbols);
                            Randpassfield.setText(password);
                        }

                        if (case1 && !case2 && case3 && !case4) {
                            String password = generatePassword(CharacterRead, NonCaps + Numbers);
                            Randpassfield.setText(password);
                        }
                        if (!case1 && !case2 && !case3 && !case4) {
                            JOptionPane.showMessageDialog(exit, "Nothing is selected.");

                        }
                    }
                }
            }
        } catch (NumberFormatException e) {

            JOptionPane.showMessageDialog(exit, "Value Must be Numbers");
        }

    }//GEN-LAST:event_GenerBtnActionPerformed

    private void upcaseCheckActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_upcaseCheckActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_upcaseCheckActionPerformed

    private void RandpassfieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_RandpassfieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_RandpassfieldActionPerformed

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed

        try {
            Socket ClientSocket = new Socket("localhost", 5555);
            System.out.println("Connection Established");

            final String secretKey = "ThisIsTheSecret";

            //sending and receiving over data on sockets            
            Scanner r = new Scanner(ClientSocket.getInputStream());
            PrintStream p = new PrintStream(ClientSocket.getOutputStream());

            //hashing password to send to server
            String password = jTextField1.getText();
            String Hashpass = PasswordHasher(password);
            //System.out.println(Hashpass);

            //encrypting the hashed password
            String originalString = Hashpass;
            String encryptedString = PasswordScreen.encrypt(originalString, secretKey);
            //System.out.println(encryptedString);
            p.println(encryptedString);

            //Recieve from server 
            int number;
            number = r.nextInt();
            //System.out.println(number);

            if (number == 1) {
                JOptionPane.showMessageDialog(exit, "Password exists in databse, please create new password ");
            } else if (number == 0) {
                JOptionPane.showMessageDialog(exit, "Password does not exist in databse ");
            }

            p.flush();
            r.close();
            ClientSocket.close();

        } catch (Exception e) {
            System.out.println("not connected to server");
        }

    }//GEN-LAST:event_jButton1ActionPerformed

    private void lwrcaseCheckActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_lwrcaseCheckActionPerformed

    }//GEN-LAST:event_lwrcaseCheckActionPerformed

    private void charEnterActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_charEnterActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_charEnterActionPerformed

    private void exitActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_exitActionPerformed
        // TODO add your handling code here
        System.exit(0);
    }//GEN-LAST:event_exitActionPerformed

    private void numCheckActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_numCheckActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_numCheckActionPerformed

    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;

                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(PasswordScreen.class
                    .getName()).log(java.util.logging.Level.SEVERE, null, ex);

        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(PasswordScreen.class
                    .getName()).log(java.util.logging.Level.SEVERE, null, ex);

        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(PasswordScreen.class
                    .getName()).log(java.util.logging.Level.SEVERE, null, ex);

        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(PasswordScreen.class
                    .getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                /*PasswordScreen PS = new PasswordScreen();
                PS.getContentPane().setBackground(Color.white);*/
                new PasswordScreen().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton GenerBtn;
    private javax.swing.JTextField Randpassfield;
    private javax.swing.JLabel Title;
    private javax.swing.JTextField charEnter;
    private javax.swing.JButton exit;
    private javax.swing.JButton jButton1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JTextField jTextField1;
    private javax.swing.JCheckBox lwrcaseCheck;
    private javax.swing.JCheckBox numCheck;
    private javax.swing.JCheckBox symbCheck;
    private javax.swing.JCheckBox upcaseCheck;
    // End of variables declaration//GEN-END:variables
}
