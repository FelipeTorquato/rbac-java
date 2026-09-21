package com.felip.rbac.exception;

import com.felip.rbac.model.enums.RoleName;

public class RoleNotConfiguredException extends RuntimeException {
    public RoleNotConfiguredException(RoleName roleName) {
        super("A role " + roleName + " não está configurada.");
    }
}
