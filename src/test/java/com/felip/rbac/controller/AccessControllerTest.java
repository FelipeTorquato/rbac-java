package com.felip.rbac.controller;

import com.felip.rbac.exception.GlobalExceptionHandler;
import com.felip.rbac.security.AuthorizationConfig;
import com.felip.rbac.security.BearerTokenResolver;
import com.felip.rbac.security.JwtService;
import com.felip.rbac.security.TokenBlacklistService;
import com.felip.rbac.security.UserDetailsServiceImpl;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AccessController.class)
@AutoConfigureMockMvc
@Import({
        AuthorizationConfig.class,
        BearerTokenResolver.class,
        GlobalExceptionHandler.class
})
class AccessControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private JwtService jwtService;

    @MockitoBean
    private UserDetailsServiceImpl userDetailsService;

    @MockitoBean
    private TokenBlacklistService tokenBlacklistService;

    @Test
    @WithMockUser(username = "user@app.com", roles = "USER")
    void userShouldAccessUserResource() throws Exception {
        mockMvc.perform(get("/api/v1/access/user"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authenticatedUser")
                        .value("user@app.com"))
                .andExpect(jsonPath("$.minimumRequiredRole")
                        .value("ROLE_USER"));
    }

    @Test
    @WithMockUser(roles = "USER")
    void userShouldNotAccessManagerResource() throws Exception {
        mockMvc.perform(get("/api/v1/access/manager"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ACCESS_DENIED"));
    }

    @Test
    @WithMockUser(roles = "MANAGER")
    void managerShouldAccessUserAndManagerResources() throws Exception {
        mockMvc.perform(get("/api/v1/access/user"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/v1/access/manager"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(roles = "MANAGER")
    void managerShouldNotAccessAdminResource() throws Exception {
        mockMvc.perform(get("/api/v1/access/admin"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ACCESS_DENIED"));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void adminShouldAccessEveryResource() throws Exception {
        mockMvc.perform(get("/api/v1/access/user"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/v1/access/manager"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/v1/access/admin"))
                .andExpect(status().isOk());
    }
}
