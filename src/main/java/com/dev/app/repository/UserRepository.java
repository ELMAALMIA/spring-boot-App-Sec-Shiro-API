package com.dev.app.repository;

import com.dev.app.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * JPA repository for {@link User} entities.
 *
 * <p>Atomic lockout queries ({@link #recordFailedAttempt} / {@link #resetLoginAttempts})
 * use {@code @Modifying @Query} so the increment and threshold check happen in a
 * single database statement — eliminating the TOCTOU race condition that would arise
 * from a read-modify-write cycle in application code.</p>
 */
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    /**
     * Atomically increments the failed-attempt counter for the given user.
     * If the new count reaches {@code maxAttempts}, also sets {@code lockedUntil}.
     *
     * <p>The entire decision (increment + optional lock) happens in one SQL statement,
     * so concurrent failed logins cannot both read the same counter value and both
     * believe they are the one to trigger the lock.</p>
     *
     * @param username    the target account
     * @param maxAttempts threshold at which the account is locked
     * @param lockUntil   timestamp to lock until when threshold is reached
     */
    @Modifying
    @Query("UPDATE User u SET " +
           "u.failedAttempts = u.failedAttempts + 1, " +
           "u.lockedUntil = CASE WHEN u.failedAttempts + 1 >= :max THEN :lockUntil ELSE u.lockedUntil END " +
           "WHERE u.username = :username")
    void recordFailedAttempt(@Param("username") String username,
                             @Param("max") int maxAttempts,
                             @Param("lockUntil") LocalDateTime lockUntil);

    /**
     * Resets the failed-attempt counter and clears any lockout after a successful login.
     *
     * @param username the account to reset
     */
    @Modifying
    @Query("UPDATE User u SET u.failedAttempts = 0, u.lockedUntil = NULL WHERE u.username = :username")
    void resetLoginAttempts(@Param("username") String username);
}
