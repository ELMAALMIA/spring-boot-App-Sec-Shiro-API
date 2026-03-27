package com.dev.app.repository;

import com.dev.app.entities.AuditEvent;
import com.dev.app.enums.AuditAction;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;

/**
 * Persistence layer for {@link AuditEvent} records.
 *
 * <p>Audit records are append-only — no delete or update operations
 * are exposed through this interface.</p>
 */
public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> {

    /** All events for a given actor, newest first. */
    List<AuditEvent> findByActorOrderByOccurredAtDesc(String actor);

    /** All events of a specific type since a given time (for alerting). */
    List<AuditEvent> findByActionAndOccurredAtAfter(AuditAction action, Instant since);
}
