package uz.pdp.sprint_security_jwt.payload;
import lombok.Data;

@Data
public class LoginDto {
    private String username;
    private String password;
}
