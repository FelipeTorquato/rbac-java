package com.felip.rbac.service;

import com.felip.rbac.exception.EmailAlreadyInUseException;
import com.felip.rbac.exception.RoleNotConfiguredException;
import com.felip.rbac.model.entity.Role;
import com.felip.rbac.model.entity.User;
import com.felip.rbac.model.enums.RoleName;
import com.felip.rbac.repository.RoleRepository;
import com.felip.rbac.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public User registerUser(String name, String email, String rawPassword) {
        String normalizedName = name.strip();
        String normalizedEmail = normalizeEmail(email);

        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new EmailAlreadyInUseException();
        }

        Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
                .orElseThrow(() -> new RoleNotConfiguredException(RoleName.ROLE_USER));

        User newUser = User.builder()
                .name(normalizedName)
                .email(normalizedEmail)
                .password(passwordEncoder.encode(rawPassword))
                .enabled(true)
                .roles(new HashSet<>(Set.of(userRole)))
                .build();

        return userRepository.save(newUser);
    }

    private String normalizeEmail(String email) {
        return email.strip().toLowerCase(Locale.ROOT);
    }
}
