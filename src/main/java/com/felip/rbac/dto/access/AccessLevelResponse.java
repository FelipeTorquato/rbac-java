package com.felip.rbac.dto.access;

import com.felip.rbac.model.enums.RoleName;

public record AccessLevelResponse(String authenticatedUser, RoleName minimumRequiredRole, String message) {
}
