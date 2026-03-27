package com.dev.app.exception;

/**
 * Thrown when the user lacks the required role or permission.
 */
public class UnauthorizedAccessException extends AppException {

    public UnauthorizedAccessException(String message) {
        super(message);
    }
}
