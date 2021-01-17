package com.orso.security.authServices;

import com.orso.security.models.EAuthType;
import com.orso.security.authServices.authServicesAction.IAuthService;
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
