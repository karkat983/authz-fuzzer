package io.github.authzfuzzer.api;

import jakarta.validation.constraints.NotBlank;

public record ShareRequest(@NotBlank String tenant) {}
