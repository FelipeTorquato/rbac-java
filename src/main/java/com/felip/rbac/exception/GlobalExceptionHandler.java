package com.felip.rbac.exception;

import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.*;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(EmailAlreadyInUseException.class)
    public ResponseEntity<ProblemDetail> handleEmailAlreadyInUse(EmailAlreadyInUseException exception) {
        ProblemDetail problem = ApiProblemDetails.create(
                HttpStatus.CONFLICT,
                ApiErrorCode.EMAIL_ALREADY_IN_USE,
                "Conflito no cadastro",
                exception.getMessage()
        );

        return ResponseEntity.status(HttpStatus.CONFLICT).body(problem);
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleResourceNotFound(ResourceNotFoundException exception) {
        ProblemDetail problem = ApiProblemDetails.create(
                HttpStatus.NOT_FOUND,
                ApiErrorCode.RESOURCE_NOT_FOUND,
                "Recurso não encontrado",
                exception.getMessage()
        );

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problem);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ProblemDetail> handleAuthentication(AuthenticationException exception) {
        ProblemDetail problem = ApiProblemDetails.create(
                HttpStatus.UNAUTHORIZED,
                ApiErrorCode.INVALID_CREDENTIALS,
                "Falha na autenticação",
                "E-mail ou senha inválidos."
        );

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(problem);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ProblemDetail> handleAccessDenied(AccessDeniedException exception) {
        ProblemDetail problem = ApiProblemDetails.create(
                HttpStatus.FORBIDDEN,
                ApiErrorCode.ACCESS_DENIED,
                "Acesso negado",
                "Você não possui permissão para acessar este recurso."
        );

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(problem);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ProblemDetail> handleConstraintViolation(
            ConstraintViolationException exception
    ) {
        List<FieldViolation> violations =
                exception.getConstraintViolations().stream()
                        .map(violation -> new FieldViolation(
                                violation.getPropertyPath().toString(),
                                violation.getMessage()
                        ))
                        .toList();

        ProblemDetail problem = ApiProblemDetails.create(
                HttpStatus.BAD_REQUEST,
                ApiErrorCode.VALIDATION_ERROR,
                "Requisição inválida",
                "Um ou mais parâmetros são inválidos."
        );

        problem.setProperty("violations", violations);

        return ResponseEntity.badRequest().body(problem);
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ProblemDetail> handleDataIntegrityViolation(DataIntegrityViolationException exception) {
        LOGGER.warn("Conflito de integridade ao persistir dados.");

        ProblemDetail problem = ApiProblemDetails.create(
                HttpStatus.CONFLICT,
                ApiErrorCode.DATA_CONFLICT,
                "Conflito de dados",
                "A operação conflita com os dados já existentes."
        );

        return ResponseEntity.status(HttpStatus.CONFLICT).body(problem);
    }

    @ExceptionHandler(RoleNotConfiguredException.class)
    public ResponseEntity<ProblemDetail> handleRoleNotConfigured(RoleNotConfiguredException exception) {
        LOGGER.warn("Erro na configuração de role.", exception);

        return internalServerError();
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleException(Exception exception) {
        String errorId = UUID.randomUUID().toString();

        LOGGER.error(
                "Erro não tratado. errorId={}",
                errorId,
                exception
        );

        ProblemDetail problem = ApiProblemDetails.create(
                HttpStatus.INTERNAL_SERVER_ERROR,
                ApiErrorCode.INTERNAL_ERROR,
                "Erro interno",
                "Não foi possível concluir a operação."
        );

        problem.setProperty("errorId", errorId);

        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(problem);
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<ProblemDetail> handleInvalidToken(
            InvalidTokenException exception
    ) {
        ProblemDetail problem = ApiProblemDetails.create(
                HttpStatus.UNAUTHORIZED,
                ApiErrorCode.INVALID_TOKEN,
                "Token inválido",
                exception.getMessage()
        );

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(problem);
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException exception,
            HttpHeaders headers,
            HttpStatusCode status,
            WebRequest request
    ) {
        Stream<FieldViolation> fieldErrors =
                exception.getBindingResult()
                        .getFieldErrors()
                        .stream()
                        .map(error -> new FieldViolation(
                                error.getField(),
                                error.getDefaultMessage()
                        ));

        Stream<FieldViolation> globalErrors =
                exception.getBindingResult()
                        .getGlobalErrors()
                        .stream()
                        .map(error -> new FieldViolation(
                                error.getObjectName(),
                                error.getDefaultMessage()
                        ));

        List<FieldViolation> violations =
                Stream.concat(fieldErrors, globalErrors).toList();

        ProblemDetail problem = ApiProblemDetails.create(
                HttpStatus.BAD_REQUEST,
                ApiErrorCode.VALIDATION_ERROR,
                "Requisição inválida",
                "Um ou mais campos são inválidos."
        );

        problem.setProperty("violations", violations);

        return handleExceptionInternal(
                exception,
                problem,
                headers,
                HttpStatus.BAD_REQUEST,
                request
        );
    }

    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(
            HttpMessageNotReadableException exception,
            HttpHeaders headers,
            HttpStatusCode status,
            WebRequest request
    ) {
        ProblemDetail problem = ApiProblemDetails.create(
                HttpStatus.BAD_REQUEST,
                ApiErrorCode.MALFORMED_REQUEST,
                "Corpo da requisição inválido",
                "O JSON enviado não pôde ser interpretado."
        );

        return handleExceptionInternal(
                exception,
                problem,
                headers,
                HttpStatus.BAD_REQUEST,
                request
        );
    }

    private ResponseEntity<ProblemDetail> internalServerError() {
        ProblemDetail problem = ApiProblemDetails.create(
                HttpStatus.INTERNAL_SERVER_ERROR,
                ApiErrorCode.INTERNAL_ERROR,
                "Erro interno",
                "Não foi possível concluir a operação."
        );

        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(problem);
    }
}
