package com.orso.security.services;

import com.orso.security.exception.FirebaseServiceException;

public interface FirebaseServiceInterface {
    String validateToken(String authToken) throws FirebaseServiceException;
}
