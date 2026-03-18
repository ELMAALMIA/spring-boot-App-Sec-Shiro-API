package com.dev.app.exception;

/**
 * Base class for all application-level exceptions.
 *
 * <p>All custom exceptions in this application extend {@code AppException},
 * allowing callers to catch any application-level error with a single
 * {@code catch (AppException e)} block when needed.</p>
 *
 * <p>Hierarchy:</p>
 * <pre>
 * AppException
 *   ├── AuthenticationFailedException  — invalid credentials
 *   ├── AccountLockedException         — account locked after N failed attempts
 *   ├── UnauthorizedAccessException    — insufficient role or permission
 *   └── ResourceNotFoundException      — entity not found
 * </pre>
 */
public class AppException extends RuntimeException {

    public AppException(String message) {
        super(message);
    }

    public AppException(String message, Throwable cause) {
        super(message, cause);
    }
}
