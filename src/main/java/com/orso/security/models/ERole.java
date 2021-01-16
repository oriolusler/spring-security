package com.orso.security.models;

public enum ERole {
    ROLE_USER("user"),
    ROLE_MODERATOR("moderator"),
    ROLE_ADMIN("admin");

    ERole(String role) {
    }

    public static ERole getERole(String role) {
        switch (role) {
            case "user":
                return ROLE_USER;
            case "moderator":
                return ROLE_MODERATOR;
            case "admin":
                return ROLE_ADMIN;
            default:
                return null;
        }
    }
}
