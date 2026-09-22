package com.felip.rbac.dto.user;

import com.felip.rbac.model.enums.RoleName;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.util.Set;

public record UpdateUserRolesRequest(
        @NotEmpty(message = "Informe pelo menos uma role.")
        Set<@NotNull(message = "A role não pode ser nula.") RoleName> roles
) {
}
