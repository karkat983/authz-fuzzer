package io.github.authzfuzzer.security;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import io.github.authzfuzzer.domain.AppUser;
import io.github.authzfuzzer.domain.Role;

/**
 * The authenticated caller. Tenant and role are fixed at login from the database; nothing the
 * client sends later (headers, body fields, IDs) can change them.
 */
public record AppUserPrincipal(
        Long userId, String username, String passwordHash, Long tenantId, String tenantName, Role role)
        implements UserDetails {

    static AppUserPrincipal of(AppUser user) {
        return new AppUserPrincipal(
                user.getId(),
                user.getUsername(),
                user.getPasswordHash(),
                user.getTenant().getId(),
                user.getTenant().getName(),
                user.getRole());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override
    public String getPassword() {
        return passwordHash;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String toString() {
        // never print the hash
        return "AppUserPrincipal[" + username + " @" + tenantName + " " + role + "]";
    }
}
