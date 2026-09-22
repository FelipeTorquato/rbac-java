package com.felip.rbac.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtServiceTest {

    private static final String SECRET =
            "test-secret-with-at-least-32-characters";
    private static final String ISSUER = "rbac-service-test";
    private static final long EXPIRATION_MILLIS = 900_000L;

    private final JwtService jwtService = new JwtService(
            SECRET,
            EXPIRATION_MILLIS,
            ISSUER
    );

    @Test
    void shouldGenerateTokenWithExpectedClaims() {
        UserDetails userDetails = User.withUsername("user@app.com")
                .password("password-hash")
                .roles("USER", "ADMIN")
                .build();

        String token = jwtService.generateToken(userDetails);
        DecodedJWT decodedJWT = JWT.decode(token);

        assertThat(decodedJWT.getSubject()).isEqualTo("user@app.com");
        assertThat(decodedJWT.getIssuer()).isEqualTo(ISSUER);
        assertThat(decodedJWT.getId()).isNotBlank();
        assertThat(decodedJWT.getIssuedAt()).isNotNull();
        assertThat(decodedJWT.getExpiresAt()).isNotNull();
        assertThat(decodedJWT.getClaim("roles").asList(String.class))
                .containsExactly("ROLE_ADMIN", "ROLE_USER");

        long lifetimeSeconds = decodedJWT.getExpiresAt().toInstant()
                .getEpochSecond()
                - decodedJWT.getIssuedAt().toInstant().getEpochSecond();

        assertThat(lifetimeSeconds).isEqualTo(900L);
    }

    @Test
    void shouldValidateTokenAndReturnSubject() {
        UserDetails userDetails = User.withUsername("user@app.com")
                .password("password-hash")
                .roles("USER")
                .build();

        String token = jwtService.generateToken(userDetails);

        assertThat(jwtService.validateTokenAndGetSubject(token))
                .isEqualTo("user@app.com");
    }

    @Test
    void shouldReturnNullForTamperedToken() {
        UserDetails userDetails = User.withUsername("user@app.com")
                .password("password-hash")
                .roles("USER")
                .build();

        String token = jwtService.generateToken(userDetails);

        int signatureStart = token.lastIndexOf('.') + 1;
        char original = token.charAt(signatureStart);
        char replacement = original == 'A' ? 'B' : 'A';

        String tamperedToken =
                token.substring(0, signatureStart)
                        + replacement
                        + token.substring(signatureStart + 1);

        assertThat(jwtService.validateTokenAndGetSubject(tamperedToken))
                .isNull();
    }

    @Test
    void shouldReturnNullForTokenFromAnotherIssuer() {
        UserDetails userDetails = User.withUsername("user@app.com")
                .password("password-hash")
                .roles("USER")
                .build();

        String token = jwtService.generateToken(userDetails);
        JwtService anotherIssuerService = new JwtService(
                SECRET,
                EXPIRATION_MILLIS,
                "another-issuer"
        );

        assertThat(anotherIssuerService.validateTokenAndGetSubject(token))
                .isNull();
    }

    @Test
    void shouldReturnNullForExpiredToken() {
        String expiredToken = JWT.create()
                .withIssuer(ISSUER)
                .withSubject("user@app.com")
                .withIssuedAt(Date.from(Instant.now().minusSeconds(120)))
                .withExpiresAt(Date.from(Instant.now().minusSeconds(60)))
                .sign(Algorithm.HMAC256(SECRET));

        assertThat(jwtService.validateTokenAndGetSubject(expiredToken))
                .isNull();
    }

    @Test
    void shouldReturnNullWhenSubjectIsMissing() {
        String tokenWithoutSubject = JWT.create()
                .withIssuer(ISSUER)
                .withExpiresAt(Date.from(Instant.now().plusSeconds(60)))
                .sign(Algorithm.HMAC256(SECRET));

        assertThat(jwtService.validateTokenAndGetSubject(tokenWithoutSubject))
                .isNull();
    }

    @Test
    void shouldExposeExpirationInSeconds() {
        assertThat(jwtService.getExpirationSeconds()).isEqualTo(900L);
    }

    @Test
    void shouldRejectNonPositiveExpiration() {
        assertThatThrownBy(() -> new JwtService(SECRET, 0, ISSUER))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("A expiração do JWT deve ser maior que zero");
    }
}
