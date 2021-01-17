package com.orso.security.services.servicesAction;

import com.orso.security.models.User;
import com.orso.security.payload.request.SignupRequest;

public interface IRegister {
    User registerUser(SignupRequest signUpRequest) throws Exception;
}
