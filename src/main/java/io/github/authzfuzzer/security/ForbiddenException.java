package io.github.authzfuzzer.security;

/** The caller is authenticated but their role does not grant the permission (HTTP 403). */
public class ForbiddenException extends RuntimeException {

    public ForbiddenException(String username, Permission permission) {
        super(username + " lacks " + permission);
    }
}
