package com.dev.app.service;

import com.dev.app.enums.AuditAction;

/**
 * Records security-relevant events to the persistent audit log.
 *
 * <p>All methods are fire-and-forget from the caller's perspective —
 * failures are logged as warnings and never propagate to the caller,
 * so an audit write error never breaks the primary auth flow.</p>
 */
public interface AuditService {

    /**
     * Records a security event.
     *
     * @param actor     the username performing the action ({@code "anonymous"} if unauthenticated)
     * @param action    the categorised event type
     * @param target    the username affected (may equal actor; nullable)
     * @param ipAddress source IP address of the request (nullable)
     * @param detail    optional free-text context — must never contain credentials
     */
    void record(String actor, AuditAction action, String target, String ipAddress, String detail);
}
