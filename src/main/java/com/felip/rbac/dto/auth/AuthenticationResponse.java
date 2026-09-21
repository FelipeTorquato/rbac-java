package com.felip.rbac.dto.auth;

import com.felip.rbac.dto.user.UserResponse;

public record AuthenticationResponse(
        String accessToken,
        String tokenType,
        long expiresIn,
        UserResponse user
) {
    public static AuthenticationResponse bearer(String accessToken, long expiresIn, UserResponse user) {
        return new AuthenticationResponse(accessToken, "Bearer", expiresIn, user);
    }
}
