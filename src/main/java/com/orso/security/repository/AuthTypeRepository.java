package com.orso.security.repository;

import com.orso.security.models.AuthType;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface AuthTypeRepository extends MongoRepository<AuthType, String> {
  Optional<AuthType> findByName(String name);

}
