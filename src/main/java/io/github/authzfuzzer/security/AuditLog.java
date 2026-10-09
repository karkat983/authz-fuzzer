package io.github.authzfuzzer.security;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Records every denied request with its real reason. The client only ever sees a generic 403 or
 * 404 (ADR 001); this log is where an operator learns that bravo-admin probed alpha's resources.
 * Entries go to the "authz.audit" logger and to a small in-memory buffer (for tests and a future
 * admin view).
 */
@Component
public class AuditLog {

    public enum Reason {
        ROLE_LACKS_PERMISSION,
        CROSS_TENANT_ACCESS
    }

    public record Entry(Instant at, String username, String tenant, String action, Long resourceId, Reason reason) {}

    private static final Logger LOG = LoggerFactory.getLogger("authz.audit");
    private static final int CAPACITY = 1000;

    private final Deque<Entry> recent = new ArrayDeque<>();

    public synchronized void denied(AppUserPrincipal caller, String action, Long resourceId, Reason reason) {
        Entry e = new Entry(Instant.now(), caller.username(), caller.tenantName(), action, resourceId, reason);
        LOG.warn("DENIED {} {} by {}@{} resource={}", reason, action, e.username(), e.tenant(), resourceId);
        recent.addLast(e);
        if (recent.size() > CAPACITY) {
            recent.removeFirst();
        }
    }

    public synchronized List<Entry> recent() {
        return List.copyOf(recent);
    }

    public synchronized void clear() {
        recent.clear();
    }
}
