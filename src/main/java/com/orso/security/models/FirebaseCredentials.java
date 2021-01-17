package com.orso.security.models;

import com.google.firebase.auth.FirebaseToken;

public class FirebaseCredentials {
    private final FirebaseToken decodedToken;
    private final String idToken;

    public FirebaseCredentials(FirebaseToken decodedToken, String idToken) {
        this.decodedToken = decodedToken;
        this.idToken = idToken;
    }

    public FirebaseToken getDecodedToken() {
        return decodedToken;
    }

    public String getIdToken() {
        return idToken;
    }
}
