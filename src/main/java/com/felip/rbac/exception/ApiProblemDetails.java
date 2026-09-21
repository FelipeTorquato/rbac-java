package com.felip.rbac.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;

import java.net.URI;
import java.time.Instant;
import java.util.Locale;

public final class ApiProblemDetails {

    public ApiProblemDetails() {
    }

    public static ProblemDetail create(HttpStatus status, ApiErrorCode code, String title, String detail) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setTitle(title);
        problem.setType(createType(code));
        problem.setProperty("code", code.name());
        problem.setProperty("timestamp", Instant.now());

        return problem;
    }

    public static ProblemDetail create(HttpStatus status, ApiErrorCode code, String title, String detail, String requestPath) {
        ProblemDetail problem = create(status, code, title, detail);
        problem.setInstance(URI.create(requestPath));

        return problem;
    }

    private static URI createType(ApiErrorCode code) {
        String identifier = code.name()
                .toLowerCase(Locale.ROOT)
                .replace('_', '-');

        return URI.create("urn:rbac:problem:" + identifier);
    }
}
