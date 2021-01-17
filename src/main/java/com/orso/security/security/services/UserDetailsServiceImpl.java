package com.orso.security.security.services;

import com.orso.security.models.AuthType;
import com.orso.security.models.User;
import com.orso.security.repository.UserService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserService userService;

    public UserDetailsServiceImpl(UserService userService) {
        this.userService = userService;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) {
        User user = userService.findByUsername(username);
        return UserDetailsImpl.build(user);
    }

    @Transactional
    public UserDetails loadUserByEmail(String email) throws UsernameNotFoundException {
        User user = userService.findByEmail(email);
        return UserDetailsImpl.build(user);
    }

    @Transactional
    public UserDetails loadUserByAuthServiceIdAndAuthType(String authServiceId, AuthType authType) throws UsernameNotFoundException {
        User user = userService.findByAuthServiceIdAndAuthType(authServiceId, authType);
        return UserDetailsImpl.build(user);
    }

}
