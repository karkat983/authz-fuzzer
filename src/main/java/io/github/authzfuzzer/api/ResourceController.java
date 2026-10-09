package io.github.authzfuzzer.api;

import java.net.URI;
import java.util.List;

import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.authzfuzzer.security.AppUserPrincipal;
import io.github.authzfuzzer.service.ResourceService;
import io.github.authzfuzzer.service.ShareService;

@RestController
@RequestMapping("/api/resources")
public class ResourceController {

    private final ResourceService service;
    private final ShareService shares;

    public ResourceController(ResourceService service, ShareService shares) {
        this.service = service;
        this.shares = shares;
    }

    /** Resources of the caller's own tenant. */
    @GetMapping
    List<ResourceDto> list(@AuthenticationPrincipal AppUserPrincipal caller) {
        return service.list(caller);
    }

    @GetMapping("/{id}")
    ResourceDto get(@AuthenticationPrincipal AppUserPrincipal caller, @PathVariable Long id) {
        return service.get(caller, id);
    }

    @PostMapping
    ResponseEntity<ResourceDto> create(
            @AuthenticationPrincipal AppUserPrincipal caller, @Valid @RequestBody ResourceRequest request) {
        ResourceDto created = service.create(caller, request);
        return ResponseEntity.created(URI.create("/api/resources/" + created.id()))
                .body(created);
    }

    @PutMapping("/{id}")
    ResourceDto update(
            @AuthenticationPrincipal AppUserPrincipal caller,
            @PathVariable Long id,
            @Valid @RequestBody ResourceRequest request) {
        return service.update(caller, id, request);
    }

    @DeleteMapping("/{id}")
    ResponseEntity<Void> delete(@AuthenticationPrincipal AppUserPrincipal caller, @PathVariable Long id) {
        service.delete(caller, id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/shares")
    ResponseEntity<ShareDto> share(
            @AuthenticationPrincipal AppUserPrincipal caller,
            @PathVariable Long id,
            @Valid @RequestBody ShareRequest request) {
        ShareDto grant = shares.grant(caller, id, request.tenant());
        return ResponseEntity.created(URI.create("/api/resources/" + id + "/shares/" + grant.tenant()))
                .body(grant);
    }
}
