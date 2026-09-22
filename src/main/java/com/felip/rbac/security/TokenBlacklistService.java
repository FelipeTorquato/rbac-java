package com.felip.rbac.security;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;

@Service
@RequiredArgsConstructor
public class TokenBlacklistService {
    private static final String KEY_PREFIX = "rbac:jwt:blacklist:";

    private final StringRedisTemplate redisTemplate;
    private final Clock clock;

    public void revoke(VerifiedJwt token) {
        Duration remainingLifetime = Duration.between(clock.instant(), token.expiresAt());

        if (remainingLifetime.isZero() || remainingLifetime.isNegative()) {
            return;
        }

        redisTemplate.opsForValue().set(key(token.tokenId()), "1", remainingLifetime);
    }

    public boolean isRevoked(String tokenId) {
        return Boolean.TRUE.equals(
                redisTemplate.hasKey(key(tokenId))
        );
    }

    private String key(String tokenId) {
        return KEY_PREFIX + tokenId;
    }
}
