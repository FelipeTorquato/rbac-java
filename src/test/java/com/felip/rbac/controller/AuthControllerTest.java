package com.felip.rbac.controller;

import com.felip.rbac.dto.auth.AuthenticationResponse;
import com.felip.rbac.dto.auth.RegisterRequest;
import com.felip.rbac.dto.user.UserResponse;
import com.felip.rbac.exception.EmailAlreadyInUseException;
import com.felip.rbac.exception.GlobalExceptionHandler;
import com.felip.rbac.model.enums.RoleName;
import com.felip.rbac.security.BearerTokenResolver;
import com.felip.rbac.security.JwtAuthenticationFilter;
import com.felip.rbac.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import(GlobalExceptionHandler.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @MockitoBean
    private BearerTokenResolver bearerTokenResolver;

    @Test
    void shouldRegisterUser() throws Exception {
        UUID userId = UUID.randomUUID();
        UserResponse user = createUserResponse(userId, "felipe@app.com");

        when(authService.register(any(RegisterRequest.class)))
                .thenReturn(user);

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "name": "Felipe",
                                  "email": "felipe@app.com",
                                  "password": "uma-senha-bem-segura"
                                }
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(userId.toString()))
                .andExpect(jsonPath("$.email").value("felipe@app.com"))
                .andExpect(jsonPath("$.roles[0]").value("ROLE_USER"))
                .andExpect(jsonPath("$.password").doesNotExist());
    }

    @Test
    void shouldRejectInvalidRegistration() throws Exception {
        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "name": "",
                                  "email": "email-invalido",
                                  "password": "curta"
                                }
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(
                        MediaType.APPLICATION_PROBLEM_JSON
                ))
                .andExpect(jsonPath("$.code")
                        .value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.violations").isArray());
    }

    @Test
    void shouldReturnConflictForExistingEmail() throws Exception {
        when(authService.register(any(RegisterRequest.class)))
                .thenThrow(new EmailAlreadyInUseException());

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "name": "Felipe",
                                  "email": "felipe@app.com",
                                  "password": "uma-senha-bem-segura"
                                }
                                """))
                .andExpect(status().isConflict())
                .andExpect(content().contentTypeCompatibleWith(
                        MediaType.APPLICATION_PROBLEM_JSON
                ))
                .andExpect(jsonPath("$.code")
                        .value("EMAIL_ALREADY_IN_USE"));
    }

    @Test
    void shouldLoginAndDisableResponseCaching() throws Exception {
        UserResponse user = createUserResponse(
                UUID.randomUUID(),
                "user@app.com"
        );

        AuthenticationResponse authentication =
                AuthenticationResponse.bearer(
                        "access-token",
                        900L,
                        user
                );

        when(authService.login(any()))
                .thenReturn(authentication);

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "user@app.com",
                                  "password": "uma-senha-bem-segura"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(header().string("Pragma", "no-cache"))
                .andExpect(jsonPath("$.accessToken")
                        .value("access-token"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900))
                .andExpect(jsonPath("$.user.email")
                        .value("user@app.com"));
    }

    @Test
    void shouldReturnGenericErrorForInvalidCredentials() throws Exception {
        when(authService.login(any()))
                .thenThrow(new BadCredentialsException("Mensagem interna"));

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "user@app.com",
                                  "password": "senha-incorreta"
                                }
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code")
                        .value("INVALID_CREDENTIALS"))
                .andExpect(jsonPath("$.detail")
                        .value("E-mail ou senha inválidos."))
                .andExpect(content().string(
                        not(containsString("Mensagem interna"))
                ));
    }

    @Test
    void shouldReturnMalformedRequestForInvalidJson() throws Exception {
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{ invalid-json }"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code")
                        .value("MALFORMED_REQUEST"));
    }

    @Test
    void shouldLogoutCurrentAccessToken() throws Exception {
        when(bearerTokenResolver.resolve("Bearer access-token"))
                .thenReturn(Optional.of("access-token"));

        mockMvc.perform(post("/api/v1/auth/logout")
                        .header(
                                HttpHeaders.AUTHORIZATION,
                                "Bearer access-token"
                        ))
                .andExpect(status().isNoContent())
                .andExpect(header().string(
                        HttpHeaders.CACHE_CONTROL,
                        "no-store"
                ))
                .andExpect(header().string(
                        HttpHeaders.PRAGMA,
                        "no-cache"
                ));

        verify(authService).logout("access-token");
    }

    private UserResponse createUserResponse(UUID id, String email) {
        return new UserResponse(
                id,
                "User",
                email,
                true,
                LocalDateTime.now(),
                List.of(RoleName.ROLE_USER)
        );
    }
}
