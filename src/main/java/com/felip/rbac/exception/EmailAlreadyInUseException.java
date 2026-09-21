package com.felip.rbac.exception;

public class EmailAlreadyInUseException extends RuntimeException {
    public EmailAlreadyInUseException() {
        super("O email informado já está em uso.");
    }
}
