package com.dev.app.entities;

import com.dev.app.enums.AuditAction;
import jakarta.persistence.*;

import java.time.Instant;

/**
 * Persistent record of every security-relevant action in the system.
 *
 * <p>Supports incident response, compliance (GDPR Art. 32, SOC2 CC6.1),
 * and anomaly detection. Written by {@code AuditService} and never
 * modified after creation — audit records are append-only.</p>
 *
 * <h3>Fields</h3>
 * <ul>
 *   <li>{@code actor}      — username who initiated the action (or {@code anonymous})</li>
 *   <li>{@code action}     — categorised event type ({@link AuditAction})</li>
 *   <li>{@code target}     — affected username (may equal actor or be a third party)</li>
 *   <li>{@code ipAddress}  — source IP at the time of the request</li>
 *   <li>{@code occurredAt} — wall-clock timestamp in UTC</li>
 *   <li>{@code detail}     — optional free-text context (never contains credentials)</li>
 * </ul>
 */
@Entity
@Table(name = "audit_events", indexes = {
        @Index(name = "idx_audit_actor",      columnList = "actor"),
        @Index(name = "idx_audit_occurred_at", columnList = "occurred_at")
})
public class AuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 50)
    private String actor;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private AuditAction action;

    @Column(length = 50)
    private String target;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    @Column(length = 255)
    private String detail;

    protected AuditEvent() {}

    private AuditEvent(Builder b) {
        this.actor       = b.actor;
        this.action      = b.action;
        this.target      = b.target;
        this.ipAddress   = b.ipAddress;
        this.occurredAt  = Instant.now();
        this.detail      = b.detail;
    }

    // ── Getters (no setters — append-only) ──────────────────────────────

    public Long        getId()         { return id; }
    public String      getActor()      { return actor; }
    public AuditAction getAction()     { return action; }
    public String      getTarget()     { return target; }
    public String      getIpAddress()  { return ipAddress; }
    public Instant     getOccurredAt() { return occurredAt; }
    public String      getDetail()     { return detail; }

    // ── Builder ──────────────────────────────────────────────────────────

    public static Builder builder(String actor, AuditAction action) {
        return new Builder(actor, action);
    }

    public static final class Builder {
        private final String      actor;
        private final AuditAction action;
        private String target;
        private String ipAddress;
        private String detail;

        private Builder(String actor, AuditAction action) {
            this.actor  = actor;
            this.action = action;
        }

        public Builder target(String target)         { this.target    = target;    return this; }
        public Builder ipAddress(String ipAddress)   { this.ipAddress = ipAddress; return this; }
        public Builder detail(String detail)         { this.detail    = detail;    return this; }
        public AuditEvent build()                    { return new AuditEvent(this); }
    }
}
