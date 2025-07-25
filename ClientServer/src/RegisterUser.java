import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Scanner;
import org.mindrot.jbcrypt.BCrypt;

public class RegisterUser {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter new username: ");
        String username = scanner.nextLine();
        System.out.print("Enter password: ");
        String password = scanner.nextLine();


        String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());

        String url = System.getenv("DB_URL");
        String user = System.getenv("DB_USER");
        String dbPassword = System.getenv("DB_PASSWORD");

        try (Connection conn = DriverManager.getConnection(url, user, dbPassword)) {
            String sql = "INSERT INTO users (username, password_hash) VALUES (?, ?)";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1, username);
            stmt.setString(2, hashedPassword);
            stmt.executeUpdate();
            System.out.println("User registered successfully!");
        } catch (SQLException e) {
            System.err.println("Error registering user: " + e.getMessage());
        }
    }
}
