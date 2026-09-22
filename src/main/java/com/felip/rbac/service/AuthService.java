package com.felip.rbac.service;

import com.felip.rbac.dto.auth.AuthenticationResponse;
import com.felip.rbac.dto.auth.LoginRequest;
import com.felip.rbac.dto.auth.RegisterRequest;
import com.felip.rbac.dto.user.UserResponse;
import com.felip.rbac.exception.InvalidTokenException;
import com.felip.rbac.model.entity.User;
import com.felip.rbac.security.CustomUserDetails;
import com.felip.rbac.security.JwtService;
import com.felip.rbac.security.TokenBlacklistService;
import com.felip.rbac.security.VerifiedJwt;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final JwtService jwtService;
    private final TokenBlacklistService tokenBlacklistService;

    public UserResponse register(RegisterRequest request) {
        User user = userService.registerUser(
                request.name(),
                request.email(),
                request.password()
        );

        return UserResponse.from(user);
    }

    public AuthenticationResponse login(LoginRequest request) {
        UsernamePasswordAuthenticationToken credentials = new UsernamePasswordAuthenticationToken(
                request.email(),
                request.password()
        );

        var authentication = authenticationManager.authenticate(credentials);

        if (!(authentication.getPrincipal() instanceof CustomUserDetails principal)) {
            throw new IllegalStateException("Principal de autenticação inesperado.");
        }

        String accessToken = jwtService.generateToken(principal);

        return AuthenticationResponse.bearer(
                accessToken,
                jwtService.getExpirationSeconds(),
                UserResponse.from(principal.getUser())
        );
    }

    public void logout(String accessToken) {
        VerifiedJwt verifiedToken = jwtService.verify(accessToken)
                .orElseThrow(InvalidTokenException::new);

        tokenBlacklistService.revoke(verifiedToken);
    }
}
