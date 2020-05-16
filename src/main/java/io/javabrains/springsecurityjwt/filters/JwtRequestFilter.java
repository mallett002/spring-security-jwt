package io.javabrains.springsecurityjwt.filters;

import io.javabrains.springsecurityjwt.services.MyUserDetailsService;
import io.javabrains.springsecurityjwt.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component // add to spring's radar
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private MyUserDetailsService userDetailsService;

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain) throws ServletException, IOException {
        // Examine incoming request for jwt in header
        // if finds valid jwt
            // gets userDetails from userDetailsService and save it into the security context

        final String authorizationHeader = request.getHeader("Authorization");
        String username = null;
        String jwt = null;

        // Get jwt and username from header
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            username = jwtUtil.extractUsername(jwt);
        }

        // if valid jwt, create token and add it to the security context
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            if (jwtUtil.validateToken(jwt, userDetails)) { // if jwt is valid
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken( // create a new authentication token
                    userDetails,
                    null,
                    userDetails.getAuthorities()
                );

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)); // set details of request on the auth token

                SecurityContextHolder.getContext().setAuthentication(authToken); // add the auth token to the security context
            }
        }

        chain.doFilter(request, response); // continue the chain
    }
}
