package com.orso.security.services.servicesAction;

import com.orso.security.payload.request.LoginRequest;
import com.orso.security.payload.response.JwtResponse;

import javax.security.auth.login.LoginException;

public interface ILogin {
    JwtResponse loginUser(LoginRequest loginRequest) throws LoginException;
}
