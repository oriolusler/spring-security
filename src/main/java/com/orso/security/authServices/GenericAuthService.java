package com.orso.security.authServices;

import com.orso.security.exception.SignUpException;
import com.orso.security.models.*;
import com.orso.security.payload.request.SignupRequest;
import com.orso.security.payload.response.JwtResponse;
import com.orso.security.security.jwt.JwtUtils;
import com.orso.security.security.services.UserDetailsImpl;
import com.orso.security.authServices.authServicesAction.IAuthService;
import com.orso.security.authServices.authServicesAction.ILogin;
import com.orso.security.authServices.authServicesAction.IRegister;
import com.orso.security.services.AuthTypeService;
import com.orso.security.services.RoleService;
import com.orso.security.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.orso.security.general.GeneralMessages.ROLE_NOT_SUPPORTED;
import static com.orso.security.models.ERole.*;
import static com.orso.security.models.ERole.ROLE_USER;

public abstract class GenericAuthService implements IAuthService, ILogin, IRegister {

    @Autowired
    private UserService userService;

    @Autowired
    private RoleService roleService;

    @Autowired
    private AuthTypeService authTypeService;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private PasswordEncoder encoder;

    public UserService getUserService() {
        return this.userService;
    }

    public JwtResponse logUserIntoApplication(Authentication authentication) {
        addAuthenticationInSpringContext(authentication);
        return generateJwtResponse(authentication);
    }

    private void addAuthenticationInSpringContext(Authentication authentication) {
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private JwtResponse generateJwtResponse(Authentication authentication) {
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return new JwtResponse(
                jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles
        );
    }

    public PasswordEncoder getEncoder() {
        return this.encoder;
    }

    public AuthType getAuthType(EAuthType authType) {
        return authTypeService.findByName(authType);
    }

    public Set<Role> prepareNewUserRoles(SignupRequest signUpRequest) throws SignUpException {
        Set<Role> roles = new HashSet<>();
        Set<String> strRoles = signUpRequest.getRoles();

        // If no roll is provided, user role will be assigned
        if (strRoles == null || strRoles.isEmpty()) {
            Role userRole = roleService.findByName(ROLE_USER);
            roles.add(userRole);
            return roles;
        }

        for (String roleString : strRoles) {
            ERole eRole = ERole.getERole(roleString);

            if (eRole == null) {
                throw new SignUpException(String.format(ROLE_NOT_SUPPORTED, roleString));
            }

            switch (eRole) {
                case ROLE_ADMIN:
                    Role adminRole = roleService.findByName(ROLE_ADMIN);
                    roles.add(adminRole);
                    break;
                case ROLE_MODERATOR:
                    Role modRole = roleService.findByName(ROLE_MODERATOR);
                    roles.add(modRole);
                    break;
                case ROLE_USER:
                default:
                    Role userRole = roleService.findByName(ROLE_USER);
                    roles.add(userRole);
            }
        }
        return roles;
    }

    public User saveUser(User user) {
        return userService.save(user);
    }

    public List<String> checkIfEmailExists(String email) {
        List<String> errors = new ArrayList<>();

        if (getUserService().existsByEmail(email)) {
            errors.add("Email is already in use!");
        }

        return errors;
    }


}
