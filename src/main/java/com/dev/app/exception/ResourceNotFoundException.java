package com.dev.app.exception;

/**
 * Thrown when a requested resource (user, role, etc.) is not found.
 */
public class ResourceNotFoundException extends AppException {

    public ResourceNotFoundException(String resource, Long id) {
        super(resource + " not found with id: " + id);
    }

    public ResourceNotFoundException(String resource, String identifier) {
        super(resource + " not found: " + identifier);
    }
}
