package com.felip.rbac.controller;

import com.felip.rbac.dto.user.UpdateUserRolesRequest;
import com.felip.rbac.dto.user.UserResponse;
import com.felip.rbac.model.entity.User;
import com.felip.rbac.security.CustomUserDetails;
import com.felip.rbac.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/me")
    public ResponseEntity<UserResponse> currentUser(@AuthenticationPrincipal(errorOnInvalidType = true) CustomUserDetails principal) {
        UserResponse response = UserResponse.from(principal.getUser());

        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body(response);
    }

    @PutMapping("/{userId}/roles")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserResponse> replaceRoles(@PathVariable UUID userId, @Valid @RequestBody UpdateUserRolesRequest request) {
        User user = userService.replaceRoles(userId, request.roles());
        UserResponse response = UserResponse.from(user);

        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body(response);
    }
}
