
import java.io.*;
import java.net.*;
import java.security.*;
import java.sql.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

class Connect {

    private Connection conn;
    private Statement stat;
    private ResultSet rs;

    public Connect() {
        try {
            Class.forName("com.mysql.jdbc.Driver");

            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/passworddb?autoReconnect=true&useSSL=false", "root", "Westminster2018");
            stat = conn.createStatement();

        } catch (Exception E) {
            System.out.println("Error Connecting" + E);
        }
    }

    public int GetData(String decryptedString) throws SQLException {
        try {

            String query = String.format("select count(*) from passdb where hashes = '%s'", decryptedString);
            rs = stat.executeQuery(query);

            rs.next();
            int hashCount = rs.getInt(1);
            //System.out.println(hashCount);

        } catch (Exception E) {
            System.out.println("Error: " + E);
        }
        return rs.getInt(1);
    }
}

class Server {

    private static SecretKeySpec secretKey;
    private static byte[] key;

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

    public static String decrypt(String strToDecrypt, String secret) {
        try {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    public static void main(String argv[]) throws Exception {

        System.out.println("Server is Running  \n" + "Waiting for client...");
        ServerSocket srvSocket = new ServerSocket(5555);

        while (true) {
            final String secretKey = "ThisIsTheSecret";
            
            Socket SocketConnection = srvSocket.accept();

            Scanner r = new Scanner(SocketConnection.getInputStream());
            PrintStream p = new PrintStream(SocketConnection.getOutputStream());

            System.out.println("Client is connected. ");
            String data;
            data = r.nextLine();
            //System.out.println(data);
            String decryptedString = Server.decrypt(data, secretKey);
            //System.out.println(decryptedString);


            Connect connect = new Connect();
            int count = connect.GetData(decryptedString);
            p.println(count);
            //System.out.println("This is sent by the SQL server " + count);

            p.flush();
            r.close();
            SocketConnection.close();
        }
    }
}

/*


*/
