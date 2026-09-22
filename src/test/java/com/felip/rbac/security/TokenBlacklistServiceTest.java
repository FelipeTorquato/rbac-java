package com.felip.rbac.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TokenBlacklistServiceTest {

    private static final Instant NOW =
            Instant.parse("2026-09-22T12:00:00Z");

    @Mock
    private StringRedisTemplate redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    private TokenBlacklistService tokenBlacklistService;

    @BeforeEach
    void setUp() {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);

        tokenBlacklistService = new TokenBlacklistService(
                redisTemplate,
                clock
        );
    }

    @Test
    void shouldBlacklistTokenUsingRemainingLifetimeAsTtl() {
        VerifiedJwt token = new VerifiedJwt(
                "token-id",
                "user@app.com",
                NOW.plusSeconds(90)
        );

        when(redisTemplate.opsForValue())
                .thenReturn(valueOperations);

        tokenBlacklistService.revoke(token);

        verify(valueOperations).set(
                "rbac:jwt:blacklist:token-id",
                "1",
                Duration.ofSeconds(90)
        );
    }

    @Test
    void shouldNotStoreAlreadyExpiredToken() {
        VerifiedJwt token = new VerifiedJwt(
                "token-id",
                "user@app.com",
                NOW.minusSeconds(1)
        );

        tokenBlacklistService.revoke(token);

        verify(redisTemplate, never()).opsForValue();
    }

    @Test
    void shouldReportRevokedToken() {
        when(redisTemplate.hasKey(
                "rbac:jwt:blacklist:token-id"
        )).thenReturn(true);

        assertThat(tokenBlacklistService.isRevoked("token-id"))
                .isTrue();
    }

    @Test
    void shouldReportTokenNotRevoked() {
        when(redisTemplate.hasKey(
                "rbac:jwt:blacklist:token-id"
        )).thenReturn(false);

        assertThat(tokenBlacklistService.isRevoked("token-id"))
                .isFalse();
    }
}