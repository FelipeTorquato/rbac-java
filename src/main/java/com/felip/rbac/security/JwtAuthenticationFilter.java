package com.felip.rbac.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsServiceImpl userDetailsService;
    private final TokenBlacklistService tokenBlacklistService;
    private final BearerTokenResolver bearerTokenResolver;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Optional<String> bearerToken = bearerTokenResolver.resolve(request.getHeader(HttpHeaders.AUTHORIZATION));

        if (bearerToken.isEmpty()) {
            filterChain.doFilter(request, response);
            return;
        }

        Optional<VerifiedJwt> verifiedJwt = jwtService.verify(bearerToken.get());

        if (verifiedJwt.isEmpty()) {
            SecurityContextHolder.clearContext();
            filterChain.doFilter(request, response);
            return;
        }

        VerifiedJwt token = verifiedJwt.get();

        if (tokenBlacklistService.isRevoked(token.tokenId())) {
            SecurityContextHolder.clearContext();
            filterChain.doFilter(request, response);
            return;
        }

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            authenticate(request, token.subject());
        }

        filterChain.doFilter(request, response);
    }

    private void authenticate(
            HttpServletRequest request,
            String userEmail
    ) {
        try {
            UserDetails userDetails =
                    userDetailsService.loadUserByUsername(userEmail);

            if (!userDetails.isEnabled()) {
                SecurityContextHolder.clearContext();
                return;
            }

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

            authentication.setDetails(
                    new WebAuthenticationDetailsSource()
                            .buildDetails(request)
            );

            SecurityContextHolder.getContext()
                    .setAuthentication(authentication);
        } catch (UsernameNotFoundException exception) {
            SecurityContextHolder.clearContext();
        }
    }
}
