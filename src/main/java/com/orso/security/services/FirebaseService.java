package com.orso.security.services;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import com.orso.security.exception.FirebaseServiceException;
import com.orso.security.exception.SignUpException;
import com.orso.security.models.FirebaseCredentials;
import com.orso.security.models.User;
import com.orso.security.payload.request.LoginRequest;
import com.orso.security.payload.request.SignupRequest;
import com.orso.security.payload.response.JwtResponse;
import com.orso.security.security.firebase.FirebaseAuthenticationProvider;
import com.orso.security.services.servicesAction.IValidateExternalServiceToken;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import javax.security.auth.login.LoginException;
import java.util.ArrayList;
import java.util.List;

import static com.orso.security.models.EAuthType.FIREBASE;

@Service
public class FirebaseService extends GenericAuthService implements IValidateExternalServiceToken {

    private final FirebaseAuthenticationProvider firebaseAuthenticationProvider;

    public FirebaseService(FirebaseAuthenticationProvider firebaseAuthenticationProvider) {
        this.firebaseAuthenticationProvider = firebaseAuthenticationProvider;
    }

    @Override
    public JwtResponse loginUser(LoginRequest loginRequest) throws LoginException {
        String token = loginRequest.getToken();
        FirebaseToken firebaseToken = getFirebaseToken(token);
        User user = getUserService().findByAuthServiceIdAndAuthType(firebaseToken.getUid(), getAuthType(FIREBASE));
        FirebaseCredentials firebaseCredentials = new FirebaseCredentials(firebaseToken, token);

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(
                        user,
                        firebaseCredentials,
                        null
                );

        Authentication authentication = firebaseAuthenticationProvider.authenticate(usernamePasswordAuthenticationToken);

        return logUserIntoApplication(authentication);
    }

    @Override
    public User registerUser(SignupRequest signUpRequest) throws Exception {
        FirebaseToken firebaseToken = getFirebaseToken(signUpRequest.getFirebaseToken());

        checkIfUserExists(firebaseToken);
        User newUser = createUser(firebaseToken);
        newUser.setRoles(prepareNewUserRoles(signUpRequest));

        return saveUser(newUser);
    }

    private void checkIfUserExists(FirebaseToken firebaseToken) throws SignUpException {
        List<String> errors = new ArrayList<>();

        errors.addAll(checkIfEmailExists(firebaseToken.getEmail()));
        errors.addAll(checkFirebaseSignUpRequest(firebaseToken));

        if (!errors.isEmpty()) {
            throw new SignUpException(errors);
        }
    }

    private void setFirebaseInfo(final User user, final FirebaseToken firebaseToken) {
        user.setAuthServiceId(firebaseToken.getUid());
        user.setEmail(firebaseToken.getEmail());
    }

    private FirebaseToken getFirebaseToken(String token) throws LoginException {
        try {
            return validateToken(token);
        } catch (FirebaseServiceException e) {
            throw new LoginException("Error while login with Firebase: " + e.getMessage());
        }
    }

    private User firebaseTokenToUserDto(FirebaseToken decodedToken) {
        User user = null;
        if (decodedToken != null) {
            user = new User();
            user.setEmail(decodedToken.getEmail());
        }
        return user;
    }

    private List<String> checkFirebaseSignUpRequest(FirebaseToken firebaseToken) {
        List<String> errors = new ArrayList<>();

        if (getUserService().existsByAuthServiceIdAndAuthType(firebaseToken.getUid(), getAuthType(FIREBASE))) {
            errors.add("User already used in Firebase");
        }

        return errors;
    }

    public User createUser(FirebaseToken firebaseToken) {
        User newUser = new User();
        newUser.setAuthType(getAuthType(FIREBASE));
        setFirebaseInfo(newUser, firebaseToken);
        return newUser;
    }

    @Override
    public FirebaseToken validateToken(String authToken) throws FirebaseServiceException {
        if (authToken == null || StringUtils.isEmpty(authToken))
            throw new FirebaseServiceException("Token is empty");

        try {
            return FirebaseAuth.getInstance().verifyIdToken(authToken);

        } catch (FirebaseAuthException e) {
            throw new FirebaseServiceException("An error has occurred while decoding Firebase token");
        }
    }
}
