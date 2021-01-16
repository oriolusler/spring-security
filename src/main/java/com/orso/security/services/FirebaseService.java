package com.orso.security.services;

import com.orso.security.exception.FirebaseServiceException;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

@Service
public class FirebaseService implements FirebaseServiceInterface {

    @Override
    public String validateToken(String authToken) throws FirebaseServiceException {
        if (authToken == null || StringUtils.isEmpty(authToken))
            throw new FirebaseServiceException("Token is empty");

        try {
            FirebaseToken decodedToken = FirebaseAuth.getInstance().verifyIdToken(authToken);
            return decodedToken.getUid();

        } catch (FirebaseAuthException e) {
            throw new FirebaseServiceException("An error has occurred while decoding Firebase token");
        }
    }
}
