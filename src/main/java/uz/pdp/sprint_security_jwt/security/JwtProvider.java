package uz.pdp.sprint_security_jwt.security;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtProvider {
    static String secretKey = "secretword";
    static long expireTime = 36_000_000;

    public String generateToken(String username){
        Date expireDate = new Date(System.currentTimeMillis()+expireTime); // 10 hours
        String token = Jwts
                .builder()
                .setSubject(username)   // unique field from user
                .setIssuedAt(new Date())          // token given date
                .setExpiration(expireDate)        // token expire date
                .signWith(SignatureAlgorithm.HS512, secretKey) // token key
                .compact(); // wrap them up

        return token;
    }

    public boolean validateToken(String token){
        try{
            Jwts
                    .parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();
            return true;

        } catch (Exception e){
                e.printStackTrace();
        }
        return false;
    }

    public String getUsernameFromToken(String token){
        String username = Jwts
                                .parser()
                                .setSigningKey(secretKey)
                                .parseClaimsJws(token)
                                .getBody()
                                .getSubject();
        return username;
    }

//    public static void main(String[] args) {
//        String token = generateToken("userLogin");
//        System.out.println(token);
//    }
}


