package io.github.authzfuzzer.api;

import io.github.authzfuzzer.domain.Resource;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body of create and update requests. It deliberately has no tenant field: the tenant
 * always comes from the authenticated caller, never from the client.
 */
public record ResourceRequest(
        @NotBlank @Size(max = Resource.MAX_NAME) String name,
        @NotBlank @Size(max = Resource.MAX_CONTENT) String content) {
}
