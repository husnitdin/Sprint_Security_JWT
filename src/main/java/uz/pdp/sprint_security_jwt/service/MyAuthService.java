package uz.pdp.sprint_security_jwt.service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Service
public class MyAuthService implements UserDetailsService {

    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<User> userList = new ArrayList<>(
                Arrays.asList(
                        new User("pdp", passwordEncoder.encode( "pdpUz"), new ArrayList<>()),
                        new User("ecma", passwordEncoder.encode("ecmaUz"), new ArrayList<>()),
                        new User("aif", passwordEncoder.encode("aifUz"), new ArrayList<>())
                )
        );
        for (User each : userList) {
            if(each.getUsername().equals(username))
                return each;
        }
        throw new UsernameNotFoundException("user not found");
    }
}
