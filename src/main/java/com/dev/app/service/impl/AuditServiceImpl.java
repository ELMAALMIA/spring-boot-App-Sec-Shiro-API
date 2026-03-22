package com.dev.app.service.impl;

import com.dev.app.entities.AuditEvent;
import com.dev.app.enums.AuditAction;
import com.dev.app.repository.AuditEventRepository;
import com.dev.app.service.AuditService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Persists audit events to the {@code audit_events} table.
 *
 * <h3>Transaction isolation</h3>
 * Each call runs in its own {@code REQUIRES_NEW} transaction so that
 * an audit write never rolls back alongside the primary operation
 * (e.g., a failed login still produces an audit record even if the
 * outer transaction rolls back for any reason).
 *
 * <h3>Fault tolerance</h3>
 * Any persistence error is caught and logged as a warning — the
 * method never throws, so audit failures are invisible to callers.
 */
@Service
public class AuditServiceImpl implements AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditServiceImpl.class);

    private final AuditEventRepository auditEventRepository;

    public AuditServiceImpl(AuditEventRepository auditEventRepository) {
        this.auditEventRepository = auditEventRepository;
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(String actor,
                       AuditAction action,
                       String target,
                       String ipAddress,
                       String detail) {
        try {
            AuditEvent event = AuditEvent.builder(actor, action)
                    .target(target)
                    .ipAddress(ipAddress)
                    .detail(detail)
                    .build();

            auditEventRepository.save(event);
            log.debug("Audit: action={} actor={} target={} ip={}", action, actor, target, ipAddress);

        } catch (Exception ex) {
            // Audit failure must never break the primary auth flow.
            log.warn("Failed to persist audit event: action={} actor={} — {}",
                    action, actor, ex.getMessage());
        }
    }
}
