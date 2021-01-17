package com.orso.security.security.firebase;


import com.orso.security.models.AuthType;
import com.orso.security.models.User;
import com.orso.security.repository.AuthTypeService;
import com.orso.security.security.services.UserDetailsServiceImpl;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

import static com.orso.security.models.EAuthType.FIREBASE;

@Component
public class FirebaseAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsServiceImpl userDetailsService;
    private final AuthTypeService authTypeService;

    public FirebaseAuthenticationProvider(UserDetailsServiceImpl userDetailsService, AuthTypeService authTypeService) {
        this.userDetailsService = userDetailsService;
        this.authTypeService = authTypeService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        User user = (User) authentication.getPrincipal();
        AuthType authType = authTypeService.findByName(FIREBASE);

        UserDetails userDetails = userDetailsService.loadUserByAuthServiceIdAndAuthType(
                user.getAuthServiceId(),
                authType
        );

        return new FirebaseAuthenticationToken(
                userDetails,
                authentication.getCredentials(),
                getAuthorities(userDetails)
        );
    }

    private List<SimpleGrantedAuthority> getAuthorities(UserDetails userDetails) {
        return userDetails.getAuthorities().stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getAuthority()))
                .collect(Collectors.toList());
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(aClass));
    }

}