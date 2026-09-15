package com.felip.rbac.service;

import com.felip.rbac.model.entity.Role;
import com.felip.rbac.model.entity.User;
import com.felip.rbac.model.enums.RoleName;
import com.felip.rbac.repository.RoleRepository;
import com.felip.rbac.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public User registerUser(String name, String email, String rawPassword) {
        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("Email já está em uso.");
        }

        Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
                .orElseThrow(() -> new IllegalStateException("Role padrão não encontrada."));

        User newUser = User.builder()
                .name(name)
                .email(email)
                .password(passwordEncoder.encode(rawPassword))
                .enabled(true)
                .roles(Set.of(userRole))
                .build();

        return userRepository.save(newUser);
    }
}
