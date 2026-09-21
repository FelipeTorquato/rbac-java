package com.felip.rbac.exception;

public class ResourceNotFoundException extends RuntimeException {
    public ResourceNotFoundException(String resource) {
        super(resource + " não encontrado.");
    }
}
