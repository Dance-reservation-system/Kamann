package pl.kamann.infrastructure.handler;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.time.LocalDateTime;

@RestControllerAdvice
public class SecurityExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(IllegalArgumentException ex) {
        return buildResponse(HttpStatus.BAD_REQUEST, "ILLEGAL_ARGUMENT", ex.getMessage());
    }

    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<ErrorResponse> handleExpiredJwtException(ExpiredJwtException ex) {
        return buildResponse(HttpStatus.UNAUTHORIZED, "JWT_EXPIRED", ex.getMessage());
    }

    @ExceptionHandler(MalformedJwtException.class)
    public ResponseEntity<ErrorResponse> handleMalformedJwtException(MalformedJwtException ex) {
        return buildResponse(HttpStatus.UNAUTHORIZED, "MALFORMED_JWT", ex.getMessage());
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDeniedException(AccessDeniedException ex) {
        return buildResponse(HttpStatus.FORBIDDEN, "ACCESS_DENIED", ex.getMessage());
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentialsException(BadCredentialsException ex) {
        return buildResponse(HttpStatus.UNAUTHORIZED, "BAD_CREDENTIALS", ex.getMessage());
    }

    @ExceptionHandler(SignatureException.class)
    public ResponseEntity<ErrorResponse> handleSignatureException(SignatureException ex) {
        return buildResponse(HttpStatus.UNAUTHORIZED, "SIGNATURE_EXCEPTION", ex.getMessage());
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleUsernameNotFoundException(UsernameNotFoundException ex) {
        return buildResponse(HttpStatus.NOT_FOUND, "USERNAME_NOT_FOUND", ex.getMessage());
    }

    public ResponseEntity<ErrorResponse> buildResponse(HttpStatus status, String code, String message) {
        ErrorResponse error = new ErrorResponse(status.value(), code, message, LocalDateTime.now());
        return new ResponseEntity<>(error, status);
    }
}
