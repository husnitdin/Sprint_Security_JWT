package uz.pdp.sprint_security_jwt.security;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import uz.pdp.sprint_security_jwt.service.MyAuthService;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    JwtProvider jwtProvider;

    @Autowired
    MyAuthService myAuthService;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws ServletException, IOException {

        // get token from Request
        String currenToken = httpServletRequest.getHeader("Authorization");

        // validate if token exists and it starts with Bearer
        if(currenToken!=null && currenToken.startsWith("Bearer") ){

            // start after Bearer part
            currenToken = currenToken.substring(7);

            // validate token - if token is destroyed, expired
            boolean validateToken = jwtProvider.validateToken(currenToken);

            if(validateToken){

                // get username from token
                String username = jwtProvider.getUsernameFromToken(currenToken);

                // through username get user details
                UserDetails userDetails = myAuthService.loadUserByUsername(username);

                // created authentication through user details
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                        new UsernamePasswordAuthenticationToken(userDetails,
                                null,
                                userDetails.getAuthorities());

                // set to the system whoever entered
                SecurityContextHolder .getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);

    }
}
