package io.github.authzfuzzer.api;

import java.time.Instant;

/** What the API returns for a resource. Entities never leave the service layer. */
public record ResourceDto(Long id, String name, String content, String tenant, Instant createdAt) {}
