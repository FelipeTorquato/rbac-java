package com.felip.rbac.controller;

import com.felip.rbac.exception.GlobalExceptionHandler;
import com.felip.rbac.model.entity.Role;
import com.felip.rbac.model.entity.User;
import com.felip.rbac.model.enums.RoleName;
import com.felip.rbac.security.AuthorizationConfig;
import com.felip.rbac.security.JwtAuthenticationFilter;
import com.felip.rbac.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(UserController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import({
        AuthorizationConfig.class,
        GlobalExceptionHandler.class
})
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private UserService userService;

    @MockitoBean
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Test
    @WithMockUser(roles = "ADMIN")
    void adminShouldReplaceUserRoles() throws Exception {
        UUID userId = UUID.randomUUID();

        Role userRole = role(RoleName.ROLE_USER);
        Role managerRole = role(RoleName.ROLE_MANAGER);

        User user = User.builder()
                .id(userId)
                .name("User")
                .email("user@app.com")
                .password("password-hash")
                .enabled(true)
                .createdAt(LocalDateTime.now())
                .roles(new HashSet<>(Set.of(userRole, managerRole)))
                .build();

        when(userService.replaceRoles(eq(userId), anySet()))
                .thenReturn(user);

        mockMvc.perform(put("/api/v1/users/{userId}/roles", userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "roles": [
                                    "ROLE_USER",
                                    "ROLE_MANAGER"
                                  ]
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(userId.toString()))
                .andExpect(jsonPath("$.roles[0]").value("ROLE_MANAGER"))
                .andExpect(jsonPath("$.roles[1]").value("ROLE_USER"));
    }

    @Test
    @WithMockUser(roles = "MANAGER")
    void managerShouldNotReplaceUserRoles() throws Exception {
        UUID userId = UUID.randomUUID();

        mockMvc.perform(put("/api/v1/users/{userId}/roles", userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "roles": ["ROLE_MANAGER"]
                                }
                                """))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ACCESS_DENIED"));

        verifyNoInteractions(userService);
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void shouldRejectEmptyRoleSet() throws Exception {
        UUID userId = UUID.randomUUID();

        mockMvc.perform(put("/api/v1/users/{userId}/roles", userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "roles": []
                                }
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));

        verifyNoInteractions(userService);
    }

    private Role role(RoleName roleName) {
        return Role.builder()
                .id(UUID.randomUUID())
                .name(roleName)
                .build();
    }
}