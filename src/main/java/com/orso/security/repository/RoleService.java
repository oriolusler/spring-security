package com.orso.security.repository;

import com.orso.security.models.ERole;
import com.orso.security.models.Role;
import org.springframework.stereotype.Service;

import static com.orso.security.general.GeneralMessages.ROLE_NOT_FOUND;
import static com.orso.security.models.ERole.ROLE_USER;

@Service
public class RoleService {

    private final RoleRepository roleRepository;

    public RoleService(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    public Role findByName(ERole name) {
        return this.roleRepository.findByName(name).orElseThrow(() -> new RuntimeException(String.format(ROLE_NOT_FOUND, ROLE_USER)));
    }
}
