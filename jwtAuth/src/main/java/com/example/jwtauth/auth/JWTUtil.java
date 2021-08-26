package com.example.jwtauth.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

@Component
public class JWTUtil {
    public Jws<Claims> getAllClaimsFromToken(String authToken) {
        return  Jwts.parser()
                .setSigningKey("secret".getBytes(StandardCharsets.UTF_8))
                .parseClaimsJws(authToken);
    }
}
