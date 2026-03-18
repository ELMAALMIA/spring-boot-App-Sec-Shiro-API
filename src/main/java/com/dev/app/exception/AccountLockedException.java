package com.dev.app.exception;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Thrown when a login attempt is made against a locked account.
 *
 * <p>An account is locked after {@code N} consecutive failed login attempts
 * (default 5). It unlocks automatically after a configured duration (default 15 min)
 * or can be manually unlocked by an admin via
 * {@code POST /api/v1/admin/users/{username}/unlock}.</p>
 */
public class AccountLockedException extends RuntimeException {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final LocalDateTime lockedUntil;

    public AccountLockedException(LocalDateTime lockedUntil) {
        super("Account is locked until " + lockedUntil.format(FMT));
        this.lockedUntil = lockedUntil;
    }

    public LocalDateTime getLockedUntil() {
        return lockedUntil;
    }
}
