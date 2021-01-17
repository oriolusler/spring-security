package com.orso.security.services;

import com.orso.security.models.AuthType;
import com.orso.security.models.EAuthType;
import com.orso.security.repository.AuthTypeRepository;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class AuthTypeService {

    private final AuthTypeRepository authTypeRepository;

    public AuthTypeService(AuthTypeRepository authTypeRepository) {
        this.authTypeRepository = authTypeRepository;
    }

    public AuthType findByName(EAuthType authType) {
        return authTypeRepository.findByName(authType).orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + authType));
    }

}
