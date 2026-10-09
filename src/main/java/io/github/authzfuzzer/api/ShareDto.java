package io.github.authzfuzzer.api;

/** One grant: `tenant` may read resource `resourceId`. */
public record ShareDto(Long resourceId, String tenant) {}
