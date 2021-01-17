package com.orso.security.services;

import com.orso.security.models.AuthType;
import com.orso.security.models.User;
import com.orso.security.repository.UserRepository;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User findByUsername(String username) {
        return this.userRepository.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));
    }

    public boolean existsByUsername(String username) {
        return this.userRepository.existsByUsername(username);
    }

    public boolean existsByEmail(String email) {
        return this.userRepository.existsByEmail(email);
    }

    public boolean existsByAuthServiceIdAndAuthType(String authServiceId, AuthType authType) {
        return this.userRepository.existsByAuthServiceIdAndAuthType(authServiceId, authType);
    }

    public User findByAuthServiceIdAndAuthType(String authServiceId, AuthType authType) {
        return this.userRepository.findByAuthServiceIdAndAuthType(authServiceId, authType).orElseThrow(() -> new RuntimeException("User not found"));
    }

    public User findByEmail(String email) {
        return this.userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found"));
    }

    public User save(User userToSave) {
        return this.userRepository.save(userToSave);
    }
}
