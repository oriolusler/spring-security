package com.orso.security.services.servicesAction;

import com.google.firebase.auth.FirebaseToken;
import com.orso.security.exception.FirebaseServiceException;

public interface IValidateExternalServiceToken {
    FirebaseToken validateToken(String authToken) throws FirebaseServiceException;
}
