package com.felip.rbac.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class JwtService {

    private final long expiration;
    private final String issuer;
    private final Algorithm algorithm;
    private final JWTVerifier verifier;

    public JwtService(@Value("${jwt.secret}") String secret, @Value("${jwt.expiration}") long expiration, @Value("${jwt.issuer}") String issuer) {
        if (expiration <= 0) {
            throw new IllegalArgumentException("A expiração do JWT deve ser maior que zero");
        }
        this.expiration = expiration;
        this.issuer = issuer;
        this.algorithm = Algorithm.HMAC256(secret);
        this.verifier = JWT.require(algorithm)
                .withIssuer(issuer)
                .build();
    }

    public String generateToken(UserDetails userDetails) {
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plusMillis(expiration);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .sorted()
                .toList();

        return JWT.create()
                .withJWTId(UUID.randomUUID().toString())
                .withIssuer(issuer)
                .withSubject(userDetails.getUsername())
                .withClaim("roles", roles)
                .withIssuedAt(Date.from(issuedAt))
                .withExpiresAt(Date.from(expiresAt))
                .sign(algorithm);
    }

    public String validateTokenAndGetSubject(String token) {
        try {
            return verify(token).map(VerifiedJwt::subject).orElse(null);
        } catch (JWTVerificationException exception) {
            return null;
        }
    }

    public long getExpirationSeconds() {
        return Duration.ofMillis(expiration).toSeconds();
    }

    public Optional<VerifiedJwt> verify(String token) {
        try {
            DecodedJWT decodedJWT = verifier.verify(token);
            String tokenId = decodedJWT.getId();
            String subject = decodedJWT.getSubject();
            Date expiresAt = decodedJWT.getExpiresAt();

            if (tokenId == null || tokenId.isBlank() || subject == null || subject.isBlank() || expiresAt == null) {
                return Optional.empty();
            }

            return Optional.of(new VerifiedJwt(tokenId, subject, expiresAt.toInstant()));
        } catch (JWTVerificationException exception) {
            return Optional.empty();
        }
    }

}
