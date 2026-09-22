package com.felip.rbac.exception;

public class InvalidTokenException extends RuntimeException {
    public InvalidTokenException() {
        super("O token informado é inválido ou expirou.");
    }
}
