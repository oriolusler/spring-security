package com.orso.security.payload.request;

import com.orso.security.models.EAuthType;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

public class LoginRequest {
    @NotBlank
    @NotNull
    private String username;

    @NotBlank
    @NotNull
    private String password;

    @NotBlank
    @NotNull
    private String token;

    @NotBlank
    @NotNull
    private EAuthType authType;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public EAuthType getAuthType() {
        return authType;
    }

    public void setAuthType(EAuthType authType) {
        this.authType = authType;
    }

    public String getToken(){
        return this.token;
    }

}
