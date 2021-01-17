package com.orso.security.controllers;

import com.orso.security.exception.FirebaseServiceException;
import com.orso.security.exception.SignUpException;
import com.orso.security.models.EAuthType;
import com.orso.security.payload.request.LoginRequest;
import com.orso.security.payload.request.SignupRequest;
import com.orso.security.payload.response.JwtResponse;
import com.orso.security.payload.response.MessageResponse;
import com.orso.security.authServices.AuthServiceSelector;
import com.orso.security.authServices.authServicesAction.IAuthService;
import com.orso.security.authServices.authServicesAction.ILogin;
import com.orso.security.authServices.authServicesAction.IRegister;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private AuthServiceSelector authServiceSelector;

    @PostMapping("/signin")
    public ResponseEntity<Object> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            ILogin iLogin = (ILogin) getAuthService(loginRequest.getAuthType());
            JwtResponse jwtResponse = iLogin.loginUser(loginRequest);
            return ResponseEntity.ok(jwtResponse);

        } catch (Exception e) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("General error during signin " + e.getMessage()));
        }
    }

    private IAuthService getAuthService(EAuthType authType) throws Exception {
        return authServiceSelector.getAuthService(authType);
    }

    @PostMapping("/signup")
    public ResponseEntity<Object> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        try {
            IRegister iRegister = (IRegister) getAuthService(signUpRequest.getAuthType());
            iRegister.registerUser(signUpRequest);
            return ResponseEntity.ok(new MessageResponse("User registered successfully!"));

        } catch (SignUpException | FirebaseServiceException signUpException) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse(signUpException.getMessage()));

        } catch (Exception e) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("General error during sign up " + e.getMessage()));
        }
    }

}
