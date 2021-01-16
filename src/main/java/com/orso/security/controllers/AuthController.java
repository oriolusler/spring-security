package com.orso.security.controllers;

import com.orso.security.exception.FirebaseServiceException;
import com.orso.security.exception.LogInException;
import com.orso.security.exception.SignUpException;
import com.orso.security.models.*;
import com.orso.security.payload.request.LoginRequest;
import com.orso.security.payload.request.SignupRequest;
import com.orso.security.payload.response.JwtResponse;
import com.orso.security.payload.response.MessageResponse;
import com.orso.security.repository.AuthTypeRepository;
import com.orso.security.repository.RoleRepository;
import com.orso.security.repository.UserRepository;
import com.orso.security.security.jwt.JwtUtils;
import com.orso.security.security.services.UserDetailsImpl;
import com.orso.security.services.FirebaseServiceInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.*;
import java.util.stream.Collectors;

import static com.orso.security.general.GeneralMessages.ROLE_NOT_FOUND;
import static com.orso.security.general.GeneralMessages.ROLE_NOT_SUPPORTED;
import static com.orso.security.models.EAuthType.FIREBASE;
import static com.orso.security.models.ERole.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    AuthTypeRepository authTypeRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    FirebaseServiceInterface firebaseService;

    @Value("${orso.app.randomKey}")
    private String randomKey;


    @PostMapping("/signin")
    public ResponseEntity<Object> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            checkGeneralSignInMandatoryFields(loginRequest);
            checkFirebaseLoginRequest(loginRequest);

            Authentication authentication = processAuthentication(loginRequest);
            addAuthenticationInSpringContext(authentication);

            JwtResponse jwtResponse = generateJwtResponse(authentication);

            return ResponseEntity.ok(jwtResponse);

        } catch (LogInException e) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse(e.getMessage()));

        } catch (Exception e) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("General error during signin " + e.getMessage()));
        }
    }

    @PostMapping("/signup")
    public ResponseEntity<Object> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        try {
            checkGeneralSignUpMandatoryFields(signUpRequest);
            checkFirebaseSignUpRequest(signUpRequest);

            User newUser = createUser(signUpRequest);
            Set<Role> roles = prepareNewUserRoles(signUpRequest);

            newUser.setRoles(roles);
            userRepository.save(newUser);

            return ResponseEntity.ok(new MessageResponse("User registered successfully!"));

        } catch (SignUpException | FirebaseServiceException signUpException) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse(signUpException.getMessage()));

        } catch (Exception e) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("General error during sign up " + e.getMessage()));
        }
    }

    private JwtResponse generateJwtResponse(Authentication authentication) {
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles);
    }

    private void addAuthenticationInSpringContext(Authentication authentication) {
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private Authentication processAuthentication(LoginRequest loginRequest) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword());
        return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
    }

    private void checkGeneralSignInMandatoryFields(LoginRequest loginRequest) throws LogInException {
        List<String> errors = new ArrayList<>();

        if (loginRequest.getAuthType() == null) {
            errors.add("Must indicate auth type");
        }

        if (!errors.isEmpty()) {
            throw new LogInException(errors);
        }
    }

    private Set<Role> prepareNewUserRoles(SignupRequest signUpRequest) throws SignUpException {
        Set<Role> roles = new HashSet<>();
        Set<String> strRoles = signUpRequest.getRoles();

        // If no roll is provided, user role will be assigned
        if (strRoles == null || strRoles.isEmpty()) {
            Role userRole = roleRepository.findByName(ROLE_USER).orElseThrow(() -> new RuntimeException(String.format(ROLE_NOT_FOUND, ROLE_USER)));
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
                    Role adminRole = roleRepository.findByName(ROLE_ADMIN).orElseThrow(() -> new RuntimeException(String.format(ROLE_NOT_FOUND, ROLE_USER)));
                    roles.add(adminRole);
                    break;

                case ROLE_MODERATOR:
                    Role modRole = roleRepository.findByName(ROLE_MODERATOR).orElseThrow(() -> new RuntimeException(String.format(ROLE_NOT_FOUND, ROLE_USER)));
                    roles.add(modRole);
                    break;

                case ROLE_USER:
                default:
                    Role userRole = roleRepository.findByName(ROLE_USER).orElseThrow(() -> new RuntimeException(String.format(ROLE_NOT_FOUND, ROLE_USER)));
                    roles.add(userRole);
            }


        }
        return roles;
    }

    private User createUser(SignupRequest signUpRequest) throws Exception {
        AuthType authType = authTypeRepository.findByName(signUpRequest.getAuthType().name()).orElseThrow(Exception::new);
        String password = encoder.encode(getPassword(signUpRequest));

        String authServiceId = "";

        if (signUpRequest.getAuthType().equals(FIREBASE)) {
            authServiceId = getFirebaseAccess(signUpRequest.getFirebaseToken()).toString();
        }

        return new User(
                signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                authType,
                password,
                authServiceId
        );
    }

    private void checkFirebaseSignUpRequest(SignupRequest signUpRequest) throws SignUpException, FirebaseServiceException {
        List<String> errors = new ArrayList<>();

        if (signUpRequest.getAuthType().equals(FIREBASE)) {
            if (StringUtils.isEmpty(signUpRequest.getFirebaseToken())) {
                errors.add("You must provide a firebase token");
            } else {
                String firebaseId = getFirebaseAccess(signUpRequest.getFirebaseToken()).toString();
                if (userRepository.existsByAuthServiceId(firebaseId)) {
                    errors.add("User already used in Firebase");
                }
            }
        }

        if (!errors.isEmpty()) {
            throw new SignUpException(errors);
        }
    }

    private void checkGeneralSignUpMandatoryFields(SignupRequest signUpRequest) throws SignUpException {
        List<String> errors = new ArrayList<>();
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            errors.add("Username is already taken!");
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            errors.add("Email is already in use!");
        }

        if (!errors.isEmpty()) {
            throw new SignUpException(errors);
        }
    }

    private CharSequence getPassword(SignupRequest signUpRequest) throws SignUpException, FirebaseServiceException {
        switch (signUpRequest.getAuthType()) {
            case EMAIL_PASSWORD:
                return signUpRequest.getPassword();
            case FIREBASE:
                return generateFirebasePassword(signUpRequest);
            default:
                throw new SignUpException("Invalid auth type");
        }
    }

    private CharSequence generateFirebasePassword(LoginRequest loginRequest) throws FirebaseServiceException {
        return getFirebaseAccess(loginRequest.getPassword()) + randomKey;
    }

    private CharSequence generateFirebasePassword(SignupRequest signUpRequest) throws FirebaseServiceException {
        return getFirebaseAccess(signUpRequest.getFirebaseToken()) + randomKey;
    }

    private void checkFirebaseLoginRequest(final LoginRequest loginRequest) throws FirebaseServiceException {
        EAuthType signInType = loginRequest.getAuthType();
        Objects.requireNonNull(signInType);

        if (signInType.equals(FIREBASE)) {
            loginRequest.setPassword(generateFirebasePassword(loginRequest).toString());
        }
    }

    private CharSequence getFirebaseAccess(final String firebaseToken) throws FirebaseServiceException {
        return firebaseService.validateToken(firebaseToken);

    }
}
