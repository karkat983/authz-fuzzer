package io.github.authzfuzzer.api;

import java.util.List;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
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
}
