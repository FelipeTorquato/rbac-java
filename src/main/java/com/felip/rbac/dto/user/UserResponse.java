package com.felip.rbac.dto.user;

import com.felip.rbac.model.entity.User;
import com.felip.rbac.model.enums.RoleName;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

public record UserResponse(
        UUID id,
        String name,
        String email,
        boolean enabled,
        LocalDateTime createdAt,
        List<RoleName> roles
) {
    public static UserResponse from(User user) {
        List<RoleName> roles = user.getRoles().stream()
                .map(role -> role.getName())
                .sorted()
                .toList();

        return new UserResponse(
                user.getId(),
                user.getName(),
                user.getEmail(),
                Boolean.TRUE.equals(user.getEnabled()),
                user.getCreatedAt(),
                roles
        );
    }
}
