package com.orso.security.payload.request;

import com.orso.security.models.EAuthType;

import javax.validation.constraints.*;
import java.util.Set;

public class SignupRequest {
    @NotBlank
    @NotNull
    @Size(min = 3, max = 20)
    private String username;
 
    @NotBlank
    @NotNull
    @Size(max = 50)
    @Email
    private String email;
    
    private Set<String> roles;
    
    @NotBlank
    @Size(min = 6, max = 40)
    private String password;

    @NotNull
    @NotBlank
    private EAuthType authType;

    private String firebaseToken;

    public String getUsername() {
        return username;
    }
 
    public void setUsername(String username) {
        this.username = username;
    }
 
    public String getEmail() {
        return email;
    }
 
    public void setEmail(String email) {
        this.email = email;
    }
 
    public String getPassword() {
        return password;
    }
 
    public void setPassword(String password) {
        this.password = password;
    }
    
    public Set<String> getRoles() {
      return this.roles;
    }
    
    public void setRole(Set<String> roles) {
      this.roles = roles;
    }

    public EAuthType getAuthType() {
        return authType;
    }

    public void setAuthType(EAuthType authType) {
        this.authType = authType;
    }

    public String getFirebaseToken() {
        return firebaseToken;
    }

    public void setFirebaseToken(String firebaseToken) {
        this.firebaseToken = firebaseToken;
    }
}
