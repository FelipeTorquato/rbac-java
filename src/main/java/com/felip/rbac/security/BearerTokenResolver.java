package com.felip.rbac.security;

import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class BearerTokenResolver {
    private static final String PREFIX = "Bearer ";

    public Optional<String> resolve(String authorizationHeader) {
        if (authorizationHeader == null
                || !authorizationHeader.startsWith(PREFIX)) {
            return Optional.empty();
        }

        String token = authorizationHeader
                .substring(PREFIX.length())
                .strip();

        return token.isBlank()
                ? Optional.empty()
                : Optional.of(token);
    }
}
