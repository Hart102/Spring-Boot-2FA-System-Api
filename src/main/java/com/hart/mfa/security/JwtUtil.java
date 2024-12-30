package com.hart.mfa.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtil {

    private static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private final Date expirationTime = new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 2);


    //Create token with user email
    public String generateToke(String email) {
        Map<String, Object> claims = new HashMap<>();
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(email)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(expirationTime)
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
    }

    //Validate generated token
    public Boolean validateToken(String token, UserDetails userDetails) {
        String extractedUsername = extractUsernameFromToken(token);
        System.out.println("Extracted username: " + extractedUsername);
        return userDetails.getUsername().equals(extractedUsername) && !isTokenExpired(token);
    }

    //Extract username from token (email)
    public String extractUsernameFromToken(String token) {
        return Jwts.parserBuilder().setSigningKey(SECRET_KEY).build().parseClaimsJws(token).getBody().getSubject();
    }

    //Check if token has expired
    public Boolean isTokenExpired(String token) {
        Date expirationTime = Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY).build().parseClaimsJws(token).getBody().getExpiration();
        return expirationTime.before(new Date());
    }
}
