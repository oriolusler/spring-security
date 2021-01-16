package com.orso.security.exception;

import java.util.List;

public class SignUpException extends Exception {
    public SignUpException(List<String> errors) {
        super("Error during signup: " + errors);

    }

    public SignUpException(String error) {
        super("Error during signup: " + error);

    }
}
