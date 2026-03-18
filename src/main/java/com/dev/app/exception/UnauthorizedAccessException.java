package com.dev.app.exception;

/**
 * Thrown when the user lacks the required role or permission.
 */
public class UnauthorizedAccessException extends RuntimeException {

    public UnauthorizedAccessException(String message) {
        super(message);
    }
}
