package io.github.authzfuzzer.api;

import io.github.authzfuzzer.domain.Resource;
import io.github.authzfuzzer.domain.Tenant;

public final class ResourceMapper {

    private ResourceMapper() {
    }

    public static ResourceDto toDto(Resource r) {
        return new ResourceDto(r.getId(), r.getName(), r.getContent(), r.getTenant().getName(), r.getCreatedAt());
    }

    /** The owning tenant is a separate argument: it comes from the caller, not the request body. */
    public static Resource toEntity(ResourceRequest request, Tenant owner) {
        return new Resource(request.name(), request.content(), owner);
    }
}
