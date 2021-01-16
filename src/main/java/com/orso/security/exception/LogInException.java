package com.orso.security.exception;

import java.util.List;

public class LogInException extends Throwable {
    public LogInException(String error) {
        super("Error during login: " + error);
    }

    public LogInException(List<String> errors) {
        super("Error during login: " + errors);
    }
}
