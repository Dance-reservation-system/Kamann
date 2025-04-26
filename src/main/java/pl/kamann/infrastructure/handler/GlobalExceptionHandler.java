package pl.kamann.infrastructure.handler;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.time.LocalDateTime;

@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ErrorResponse> handleApiException(ApiException ex) {
        return buildResponse(ex.getStatus(), ex.getCode(), ex.getMessage());
    }

    public ResponseEntity<ErrorResponse> buildResponse(HttpStatus status, String code, String message) {
        ErrorResponse error = new ErrorResponse(status.value(), code, message, LocalDateTime.now());
        return new ResponseEntity<>(error, status);
    }
}