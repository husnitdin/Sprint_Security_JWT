package uz.pdp.sprint_security_jwt.controller;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import uz.pdp.sprint_security_jwt.payload.LoginDto;
import uz.pdp.sprint_security_jwt.security.JwtProvider;
import uz.pdp.sprint_security_jwt.service.MyAuthService;

import javax.xml.ws.Response;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    MyAuthService myAuthService;

    @Autowired
    JwtProvider jwtProvider;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    AuthenticationManager authenticationManager;

    @PostMapping("/login")
    public HttpEntity<?> loginToSystem(@RequestBody LoginDto loginDto){
        // UserDetails userDetails = myAuthService.loadUserByUsername(loginDto.getUsername());
        // boolean match = passwordEncoder.matches(loginDto.getPassword(), userDetails.getPassword());
        // if(match) {

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    loginDto.getUsername(),
                    loginDto.getPassword()));

            String token = jwtProvider.generateToken(loginDto.getUsername());
            return ResponseEntity.ok(token);
            // }
        } catch (BadCredentialsException exception ){
            return ResponseEntity.status(401).body( "Login or password is wrong");
        }
    }
}
