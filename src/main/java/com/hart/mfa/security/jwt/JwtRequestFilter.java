package com.hart.mfa.security.jwt;//package com.hart.mfa.security;
//
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.RequiredArgsConstructor;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
//import org.springframework.stereotype.Component;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//
//@Component
//@RequiredArgsConstructor
//public class JwtRequestFilter extends OncePerRequestFilter {
//
//    private final UserDetailsService userDetailsService;
//    private final JwtUtil jwtUtil;
//
//
//
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
//            throws ServletException, IOException {
//
//        //Get jwt token from header
//        final String authorizationHeader = request.getHeader("Authorization");
//
//        String jwtToken = null;
//        String username = null;
//
//        /*
//        * If Authorization Header is not null:
//        * Remove Bearer string from token
//        * Set username to username extracted from the token
//        * */
//        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
//            jwtToken = authorizationHeader.substring(7);
//            username = jwtUtil.extractUsernameFromToken(jwtToken);
//        }
//
//        //Check if username is not null and user not already authenticated
//        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
//
//            //Check if token is valid or not
//            if (jwtUtil.validateToken(jwtToken, userDetails)) {
//                // Create new authentication token
//                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
//                        userDetails, null
//                );
//
//                // Set authentication Details
//                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                //Create new session for the authenticated user
//                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
//            } else {
//                // If token is invalid, return a 403 Forbidden response with a custom message
//                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
//                response.setContentType("application/json");
//                response.getWriter().write("{\"message\":\"Access denied: Invalid or expired token.\"}");
//                return; // Stop further processing
//            }
//        }
//        filterChain.doFilter(request, response);
//    }
//}


import com.hart.mfa.response.ApiResponse;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static org.ietf.jgss.GSSException.UNAUTHORIZED;

@Component
@RequiredArgsConstructor
public class JwtRequestFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {


        try {
            String jwt = parseJwt(request);
            //If token is not empty and is validated:
            if (StringUtils.hasText(jwt) && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.extractUsernameFromToken(jwt);
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                Authentication auth = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
            filterChain.doFilter(request, response);

        } catch (io.jsonwebtoken.security.SignatureException e) {
            handleJwtException(response, "Invalid access token. Please login again.");
        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            handleJwtException(response, "Access token has expired. Please login again.");
        } catch (Exception e) {
            handleJwtException(response, "An error occurred during JWT processing.");
        }
    }

    // Capture request and extract token from request
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }
        return null;
    }

    private void handleJwtException(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"" + message + "\"}");
    }
}
