package com.orso.security.exception;

public class FirebaseServiceException extends Exception {
    public FirebaseServiceException(String message) {
        super("Firebase service ERROR: " + message);
    }
}
