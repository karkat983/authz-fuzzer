package io.github.authzfuzzer.api;

/** A user as seen by an admin of the same tenant. Never includes the password hash. */
public record UserDto(String username, String role, String tenant) {}
