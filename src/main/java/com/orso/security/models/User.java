package com.orso.security.models;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.util.HashSet;
import java.util.Set;

@Document(collection = "users")
public class User {
    @Id
    private String id;

    @NotBlank
    @Size(max = 20)
    private String username;

    @NotBlank
    @Size(max = 50)
    @Email
    private String email;

    @NotBlank
    @Size(max = 120)
    private String password;

    @NotBlank
    private AuthType authType;

    @DBRef
    private Set<Role> roles = new HashSet<>();

    private String authServiceId;

    public User() {
    }

    public User(String username, String email, AuthType authType, String password, String authServiceId) {
        this.username = username;
        this.email = email;
        this.password = password;
        this.authType = authType;
        this.authServiceId = authServiceId;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

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

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public AuthType getAuthType() {
        return authType;
    }

    public void setAuthType(AuthType authType) {
        this.authType = authType;
    }

    public String getAuthServiceId() {
        return authServiceId;
    }

    public void setAuthServiceId(String authServiceId) {
        this.authServiceId = authServiceId;
    }
}
