package com.felip.rbac.service;

import com.felip.rbac.exception.ResourceNotFoundException;
import com.felip.rbac.exception.RoleNotConfiguredException;
import com.felip.rbac.model.entity.Role;
import com.felip.rbac.model.entity.User;
import com.felip.rbac.model.enums.RoleName;
import com.felip.rbac.repository.RoleRepository;
import com.felip.rbac.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserService userService;

    @Test
    void shouldReplaceUserRoles() {
        UUID userId = UUID.randomUUID();

        Role userRole = role(RoleName.ROLE_USER);
        Role managerRole = role(RoleName.ROLE_MANAGER);

        User user = User.builder()
                .id(userId)
                .roles(new HashSet<>(Set.of(userRole)))
                .build();

        when(userRepository.findById(userId))
                .thenReturn(Optional.of(user));
        when(roleRepository.findByName(RoleName.ROLE_USER))
                .thenReturn(Optional.of(userRole));
        when(roleRepository.findByName(RoleName.ROLE_MANAGER))
                .thenReturn(Optional.of(managerRole));

        User updated = userService.replaceRoles(
                userId,
                Set.of(RoleName.ROLE_USER, RoleName.ROLE_MANAGER)
        );

        assertThat(updated.getRoles())
                .extracting(Role::getName)
                .containsExactlyInAnyOrder(
                        RoleName.ROLE_USER,
                        RoleName.ROLE_MANAGER
                );
    }

    @Test
    void shouldRejectUnknownUserWhenReplacingRoles() {
        UUID userId = UUID.randomUUID();

        when(userRepository.findById(userId))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.replaceRoles(
                userId,
                Set.of(RoleName.ROLE_USER)
        ))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessage("Usuário não encontrado.");

        verifyNoInteractions(roleRepository);
    }

    @Test
    void shouldRejectRoleNotConfiguredInDatabase() {
        UUID userId = UUID.randomUUID();

        User user = User.builder()
                .id(userId)
                .roles(new HashSet<>())
                .build();

        when(userRepository.findById(userId))
                .thenReturn(Optional.of(user));
        when(roleRepository.findByName(RoleName.ROLE_MANAGER))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.replaceRoles(
                userId,
                Set.of(RoleName.ROLE_MANAGER)
        ))
                .isInstanceOf(RoleNotConfiguredException.class)
                .hasMessage("A role ROLE_MANAGER não está configurada.");
    }

    private Role role(RoleName roleName) {
        return Role.builder()
                .id(UUID.randomUUID())
                .name(roleName)
                .build();
    }
}