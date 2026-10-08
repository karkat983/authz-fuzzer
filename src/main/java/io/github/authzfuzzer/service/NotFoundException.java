package io.github.authzfuzzer.service;

/** Thrown when a resource or tenant does not exist (or must look as if it does not). */
public class NotFoundException extends RuntimeException {

    public NotFoundException(String what, Object id) {
        super(what + " not found: " + id);
    }
}
