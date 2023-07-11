package com.assignment.EmployeeCompany.config;

import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

@Component
public class JwtGeneratorValidator {

    @Value("${EmployeeCompany.app.jwtSecret}")
    private String SECRET;

    @Value("${EmployeeCompany.app.jwtExpirationMs}")
    private int jwtExpirationMs;
    private final Logger logger = LoggerFactory.getLogger(JwtGeneratorValidator.class);

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, username);
    }

    private String createToken(Map<String, Object> claims, String subject) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + TimeUnit.MINUTES.toMillis(jwtExpirationMs)); // 1 minute expiration time

        String token = Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS256, SECRET)
                .compact();
        logger.trace("Generated JWT token for user '{}'", subject);
        return token;
    }

    public Boolean validateToken(String token, UserDetails userDetails) throws Exception {
        try {
            final String username = extractUsername(token);
            boolean isValid = username.equals(userDetails.getUsername()) && !isTokenExpired(token);
            if (!isValid) {
                throw new Exception("Invalid JWT token for user '" + userDetails.getUsername() + "'");
            }
            return isValid;
        } catch (ExpiredJwtException ex) {
            logger.warn("Expired JWT token for user '{}'", userDetails.getUsername());
            throw new Exception("Expired JWT token for user '" + userDetails.getUsername() + "'");
        } catch (JwtException ex) {
            logger.warn("Invalid JWT token for user '{}'", userDetails.getUsername());
            throw ex;
        } catch (Exception ex) {
            logger.error("Error validating JWT token for user '{}'", userDetails.getUsername(), ex);
            throw new Exception("Invalid JWT token for user '" + userDetails.getUsername() + "'");
        }
    }
}


//package com.assignment.EmployeeCompany.config;
//
//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.SignatureAlgorithm;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.stereotype.Component;
//
//import java.util.Date;
//import java.util.HashMap;
//import java.util.Map;
//import java.util.concurrent.TimeUnit;
//import java.util.function.Function;
//
//@Component
//public class JwtGeneratorValidator {
//
//    private final String SECRET = "Ayushi";
//    private final Logger logger = LoggerFactory.getLogger(JwtGeneratorValidator.class);
//
//    public String extractUsername(String token) {
//        return extractClaim(token, Claims::getSubject);
//    }
//
//    public Date extractExpiration(String token) {
//        return extractClaim(token, Claims::getExpiration);
//    }
//
//    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
//        final Claims claims = extractAllClaims(token);
//        return claimsResolver.apply(claims);
//    }
//
//    private Claims extractAllClaims(String token) {
//        return Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).getBody();
//    }
//
//    private Boolean isTokenExpired(String token) {
//        return extractExpiration(token).before(new Date());
//    }
//
//    public String generateToken(String username) {
//        Map<String, Object> claims = new HashMap<>();
//        return createToken(claims, username);
//    }
//
//    private String createToken(Map<String, Object> claims, String subject) {
//        Date now = new Date();
//        Date expiryDate = new Date(now.getTime() + TimeUnit.MINUTES.toMillis(1)); // 1 minutes expiration time
//
//        String token = Jwts.builder()
//                .setClaims(claims)
//                .setSubject(subject)
//                .setIssuedAt(now)
//                .setExpiration(expiryDate)
//                .signWith(SignatureAlgorithm.HS256, SECRET)
//                .compact();
//
//        logger.trace("Generated JWT token for user '{}'", subject);
//        return token;
//    }
//
//    public Boolean validateToken(String token, UserDetails userDetails) {
//        final String username = extractUsername(token);
//        boolean isValid = username.equals(userDetails.getUsername()) && !isTokenExpired(token);
//        if (!isValid) {
//            logger.warn("Invalid or expired JWT token for user '{}'", userDetails.getUsername());
//        }
//        return isValid;
//    }
//}
