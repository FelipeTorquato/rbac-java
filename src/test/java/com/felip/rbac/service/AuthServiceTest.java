package com.felip.rbac.service;

import com.felip.rbac.dto.auth.LoginRequest;
import com.felip.rbac.dto.auth.RegisterRequest;
import com.felip.rbac.exception.InvalidTokenException;
import com.felip.rbac.model.entity.Role;
import com.felip.rbac.model.entity.User;
import com.felip.rbac.model.enums.RoleName;
import com.felip.rbac.security.CustomUserDetails;
import com.felip.rbac.security.JwtService;
import com.felip.rbac.security.TokenBlacklistService;
import com.felip.rbac.security.VerifiedJwt;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private UserService userService;

    @Mock
    private JwtService jwtService;

    @Mock
    private TokenBlacklistService tokenBlacklistService;

    @InjectMocks
    private AuthService authService;

    @Test
    void shouldRegisterUserWithDefaultRole() {
        RegisterRequest request = new RegisterRequest(
                "Felipe",
                "felipe@app.com",
                "uma-senha-bem-segura"
        );

        User user = createUser("felipe@app.com");

        when(userService.registerUser(
                request.name(),
                request.email(),
                request.password()
        )).thenReturn(user);

        var response = authService.register(request);

        assertThat(response.id()).isEqualTo(user.getId());
        assertThat(response.name()).isEqualTo(user.getName());
        assertThat(response.email()).isEqualTo(user.getEmail());
        assertThat(response.enabled()).isTrue();
        assertThat(response.roles()).containsExactly(RoleName.ROLE_USER);

        verify(userService).registerUser(
                request.name(),
                request.email(),
                request.password()
        );
    }

    @Test
    void shouldAuthenticateAndGenerateAccessToken() {
        LoginRequest request = new LoginRequest(
                "user@app.com",
                "uma-senha-bem-segura"
        );

        User user = createUser(request.email());
        CustomUserDetails principal = new CustomUserDetails(user);

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        principal,
                        null,
                        principal.getAuthorities()
                );

        when(authenticationManager.authenticate(any()))
                .thenReturn(authentication);
        when(jwtService.generateToken(principal))
                .thenReturn("access-token");
        when(jwtService.getExpirationSeconds())
                .thenReturn(900L);

        var response = authService.login(request);

        assertThat(response.accessToken()).isEqualTo("access-token");
        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(response.expiresIn()).isEqualTo(900L);
        assertThat(response.user().email()).isEqualTo(request.email());
        assertThat(response.user().roles()).containsExactly(RoleName.ROLE_USER);

        ArgumentCaptor<UsernamePasswordAuthenticationToken> captor =
                ArgumentCaptor.forClass(
                        UsernamePasswordAuthenticationToken.class
                );

        verify(authenticationManager).authenticate(captor.capture());
        verify(jwtService).generateToken(principal);

        assertThat(captor.getValue().getPrincipal())
                .isEqualTo(request.email());
        assertThat(captor.getValue().getCredentials())
                .isEqualTo(request.password());
    }

    @Test
    void shouldRejectUnexpectedAuthenticationPrincipal() {
        LoginRequest request = new LoginRequest(
                "user@app.com",
                "uma-senha-bem-segura"
        );

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        "unexpected-principal",
                        null,
                        Set.of()
                );

        when(authenticationManager.authenticate(any()))
                .thenReturn(authentication);

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Principal de autenticação inesperado.");

        verify(jwtService, never()).generateToken(any());
    }

    @Test
    void shouldBlacklistAccessTokenOnLogout() {
        VerifiedJwt verifiedToken = new VerifiedJwt(
                "token-id",
                "user@app.com",
                Instant.now().plusSeconds(300)
        );

        when(jwtService.verify("access-token"))
                .thenReturn(Optional.of(verifiedToken));

        authService.logout("access-token");

        verify(tokenBlacklistService).revoke(verifiedToken);
    }

    @Test
    void shouldRejectInvalidTokenOnLogout() {
        when(jwtService.verify("invalid-token"))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.logout("invalid-token"))
                .isInstanceOf(InvalidTokenException.class);

        verify(tokenBlacklistService, never()).revoke(any());
    }

    private User createUser(String email) {
        Role role = Role.builder()
                .id(UUID.randomUUID())
                .name(RoleName.ROLE_USER)
                .build();

        return User.builder()
                .id(UUID.randomUUID())
                .name("User")
                .email(email)
                .password("password-hash")
                .enabled(true)
                .createdAt(LocalDateTime.now())
                .roles(Set.of(role))
                .build();
    }
}
