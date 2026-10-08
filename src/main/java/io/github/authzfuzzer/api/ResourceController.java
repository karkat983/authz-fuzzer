package io.github.authzfuzzer.api;

import java.net.URI;
import java.util.List;

import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.authzfuzzer.security.AppUserPrincipal;
import io.github.authzfuzzer.service.ResourceService;

@RestController
@RequestMapping("/api/resources")
public class ResourceController {

    private final ResourceService service;

    public ResourceController(ResourceService service) {
        this.service = service;
    }

    /** Resources of the caller's own tenant. */
    @GetMapping
    List<ResourceDto> list(@AuthenticationPrincipal AppUserPrincipal caller) {
        return service.list(caller.tenantId());
    }

    // Authorization (tenant + permission) is added for every endpoint in the RBAC commits 053-054.
    @GetMapping("/{id}")
    ResourceDto get(@AuthenticationPrincipal AppUserPrincipal caller, @PathVariable Long id) {
        return service.get(id);
    }

    @PostMapping
    ResponseEntity<ResourceDto> create(
            @AuthenticationPrincipal AppUserPrincipal caller, @Valid @RequestBody ResourceRequest request) {
        ResourceDto created = service.create(caller.tenantId(), request);
        return ResponseEntity.created(URI.create("/api/resources/" + created.id()))
                .body(created);
    }

    @PutMapping("/{id}")
    ResourceDto update(
            @AuthenticationPrincipal AppUserPrincipal caller,
            @PathVariable Long id,
            @Valid @RequestBody ResourceRequest request) {
        return service.update(id, request);
    }
}
