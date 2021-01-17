package com.orso.security.services;

import com.orso.security.exception.SignUpException;
import com.orso.security.models.AuthType;
import com.orso.security.models.User;
import com.orso.security.payload.request.LoginRequest;
import com.orso.security.payload.request.SignupRequest;
import com.orso.security.payload.response.JwtResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

import static com.orso.security.models.EAuthType.EMAIL_PASSWORD;

@Service
public class UserPasswordService extends GenericAuthService {

    private final AuthenticationManager authenticationManager;

    public UserPasswordService(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public JwtResponse loginUser(LoginRequest loginRequest) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                );

        Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);

        return logUserIntoApplication(authentication);
    }

    @Override
    public User registerUser(SignupRequest signUpRequest) throws Exception {
        checkIfUserExists(signUpRequest);

        User newUser = createUser(signUpRequest);
        newUser.setRoles(prepareNewUserRoles(signUpRequest));

        return saveUser(newUser);
    }

    private void checkIfUserExists(SignupRequest signUpRequest) throws SignUpException {
        List<String> errors = new ArrayList<>();

        if (getUserService().existsByUsername(signUpRequest.getUsername())) {
            errors.add("Username is already taken!");
        }

        errors.addAll(checkIfEmailExists(signUpRequest.getEmail()));

        if (!errors.isEmpty()) {
            throw new SignUpException(errors);
        }
    }

    public User createUser(SignupRequest signUpRequest) throws Exception {
        AuthType authType = getAuthType(EMAIL_PASSWORD);
        String password = getEncoder().encode(signUpRequest.getPassword());

        User newUser = new User();

        newUser.setUsername(signUpRequest.getUsername());
        newUser.setPassword(password);
        newUser.setEmail(signUpRequest.getEmail());
        newUser.setAuthType(authType);

        return newUser;
    }
}
