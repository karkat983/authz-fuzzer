package io.github.authzfuzzer.api;

import java.util.List;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.authzfuzzer.security.AppUserPrincipal;
import io.github.authzfuzzer.service.UserService;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService service;

    public UserController(UserService service) {
        this.service = service;
    }

    @GetMapping
    List<UserDto> list(@AuthenticationPrincipal AppUserPrincipal caller) {
        return service.list(caller);
    }
}
