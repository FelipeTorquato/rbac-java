package com.felip.rbac.dto.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank(message = "O nome é obrigatório.")
        @Size(min = 2, max = 100, message = "O nome deve ter entre 2 e 100 caracteres.")
        String name,

        @NotBlank(message = "O email é obrigatório.")
        @Email(message = "O email informado é inválido.")
        @Size(max = 254, message = "O email deve ter no máximo 254 caracteres.")
        String email,

        @NotBlank(message = "A senha é obrigatória.")
        @Size(min = 15, max = 72, message = "A senha deve ter entre 15 e 72 caracteres.")
        String password
) {
}
