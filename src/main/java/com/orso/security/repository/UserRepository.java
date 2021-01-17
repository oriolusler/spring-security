package com.orso.security.repository;

import com.orso.security.models.AuthType;
import com.orso.security.models.User;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface UserRepository extends MongoRepository<User, String> {
    Optional<User> findByUsername(String username);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    boolean existsByAuthServiceIdAndAuthType(String authServiceId, AuthType authType);

    Optional<User> findByAuthServiceIdAndAuthType(String authServiceId, AuthType authType);

    Optional<User> findByEmail(String email);
}
