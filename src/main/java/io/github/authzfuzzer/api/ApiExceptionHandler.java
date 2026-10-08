package io.github.authzfuzzer.api;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import io.github.authzfuzzer.security.ForbiddenException;
import io.github.authzfuzzer.service.NotFoundException;

/**
 * Maps exceptions to RFC 7807 problem responses. Not-found bodies are deliberately generic:
 * they never echo IDs or tenant names, so a 404 reveals nothing about what exists elsewhere.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(NotFoundException.class)
    ProblemDetail notFound(NotFoundException e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, "Resource not found");
    }

    @ExceptionHandler(ForbiddenException.class)
    ProblemDetail forbidden(ForbiddenException e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, "Not allowed for your role");
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ProblemDetail invalid(MethodArgumentNotValidException e) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Invalid request body");
        problem.setProperty(
                "fields",
                e.getBindingResult().getFieldErrors().stream()
                        .map(err -> err.getField())
                        .distinct()
                        .sorted()
                        .toList());
        return problem;
    }
}
