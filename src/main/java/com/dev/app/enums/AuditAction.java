package com.dev.app.enums;

/**
 * Categorises every security-relevant event written to the audit log.
 */
public enum AuditAction {

    /** Successful authentication. */
    LOGIN_SUCCESS,

    /** Failed authentication (wrong password or unknown user). */
    LOGIN_FAILURE,

    /** Account blocked — too many consecutive failures. */
    LOGIN_BLOCKED_LOCKED,

    /** User-initiated session termination. */
    LOGOUT,

    /** Admin manually cleared the lockout for an account. */
    ACCOUNT_UNLOCKED
}
