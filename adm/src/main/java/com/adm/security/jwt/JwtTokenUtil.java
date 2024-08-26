package com.adm.security.jwt;

import com.adm.entity.User;
import io.jsonwebtoken.*;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtTokenUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenUtil.class);

    public static final String TOKEN_SUBJECT = "AUTH_USER_TOKEN";
    public static final String TOKEN_ISSUER = "Adm.com";


    private static final long EXPIRE_DURATION = 24 * 60 * 60 * 100; // 24-hour

    @Value("${app_jwt_secret}")
    private String jwtSecret;

    private final Counter invalidJwtCounter;
    private final Counter expiredJwtCounter;

    public JwtTokenUtil(MeterRegistry registry) {
        invalidJwtCounter = Counter.builder("adm_backend_invalid_jwt_sum")
                .description("Number of invalid JWT in the request")
                .register(registry);

        expiredJwtCounter = Counter.builder("adm_backend_expired_jwt_sum")
                .description("Number of expired JWT in the request")
                .register(registry);
    }

    public String generateAccessToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", user.getId());
        claims.put("email", user.getEmail());

        return Jwts.builder()
                .setSubject(TOKEN_SUBJECT)
                .setIssuer(TOKEN_ISSUER)
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRE_DURATION))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .addClaims(claims)
                .compact();
    }

    public String getEmailFromJwtToken(String token) {
        Jws<Claims> claimsJws = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
        return claimsJws.getBody().get("email").toString();
    }

    public boolean validate(String authToken) {
        try {
            Jws<Claims> claimsJws = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            String tknSubject = claimsJws.getBody().getSubject();
            String tknIssuer = claimsJws.getBody().getIssuer();
            Date tknExpiration = claimsJws.getBody().getExpiration();

            return tknSubject.equals(TOKEN_SUBJECT) && tknIssuer.equals(TOKEN_ISSUER) && !tknExpiration.before(new Date());
        } catch (MalformedJwtException e) {
            invalidJwtCounter.increment();
            logger.error("Invalid JWT Token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            expiredJwtCounter.increment();
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }
}
