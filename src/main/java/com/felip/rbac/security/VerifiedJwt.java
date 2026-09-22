package com.felip.rbac.security;

import java.time.Instant;

public record VerifiedJwt(String tokenId, String subject, Instant expiresAt) {
}
