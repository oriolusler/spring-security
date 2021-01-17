package com.orso.security.services;

import com.orso.security.models.EAuthType;
import com.orso.security.services.servicesAction.IAuthService;
import org.springframework.stereotype.Service;

@Service
public class AuthServiceSelector {

    private final FirebaseService firebaseService;
    private final UserPasswordService userPasswordService;

    public AuthServiceSelector(FirebaseService firebaseService, UserPasswordService userPasswordService) {
        this.firebaseService = firebaseService;
        this.userPasswordService = userPasswordService;
    }

    public IAuthService getAuthService(EAuthType authType) throws Exception {
        switch (authType) {
            case FIREBASE:
                return firebaseService;
            case EMAIL_PASSWORD:
                return userPasswordService;
            default:
                throw new Exception("No auth service found");
        }
    }
}
