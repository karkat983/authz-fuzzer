package io.github.authzfuzzer.service;

import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.authzfuzzer.api.UserDto;
import io.github.authzfuzzer.domain.AppUserRepository;
import io.github.authzfuzzer.security.AppUserPrincipal;
import io.github.authzfuzzer.security.AuthorizationService;
import io.github.authzfuzzer.security.Permission;

@Service
@Transactional(readOnly = true)
public class UserService {

    private final AppUserRepository users;
    private final AuthorizationService authz;

    public UserService(AppUserRepository users, AuthorizationService authz) {
        this.users = users;
        this.authz = authz;
    }

    /** Users of the caller's own tenant. Admins only. */
    public List<UserDto> list(AppUserPrincipal caller) {
        authz.check(caller, Permission.MANAGE_USERS);
        return users.findAllByTenantIdOrderByUsernameAsc(caller.tenantId()).stream()
                .map(u -> new UserDto(
                        u.getUsername(), u.getRole().name(), u.getTenant().getName()))
                .toList();
    }
}
