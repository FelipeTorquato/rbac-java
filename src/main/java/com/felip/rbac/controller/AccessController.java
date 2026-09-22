package com.felip.rbac.controller;

import com.felip.rbac.dto.access.AccessLevelResponse;
import com.felip.rbac.model.enums.RoleName;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/access")
public class AccessController {

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<AccessLevelResponse> user(Authentication authentication) {
        return granted(authentication, RoleName.ROLE_USER, "Recurso disponível para USER, MANAGER e ADMIN.");
    }

    @GetMapping("/manager")
    @PreAuthorize("hasRole('MANAGER')")
    public ResponseEntity<AccessLevelResponse> manager(
            Authentication authentication
    ) {
        return granted(
                authentication,
                RoleName.ROLE_MANAGER,
                "Recurso disponível para MANAGER e ADMIN."
        );
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<AccessLevelResponse> admin(Authentication authentication) {
        return granted(
                authentication,
                RoleName.ROLE_ADMIN,
                "Recurso disponível somente para ADMIN.");
    }

    private ResponseEntity<AccessLevelResponse> granted(
            Authentication authentication,
            RoleName minimumRequiredRole,
            String message
    ) {
        AccessLevelResponse response = new AccessLevelResponse(
                authentication.getName(),
                minimumRequiredRole,
                message
        );

        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body(response);
    }
}
