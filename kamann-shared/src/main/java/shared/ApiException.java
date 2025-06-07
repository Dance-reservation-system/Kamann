package shared;


import org.springframework.http.HttpStatus;

/**
 * Ubiquitous Language Summary:
 * A generic application-layer exception used for signaling client-relevant errors.
 */
public class ApiException extends RuntimeException {

    private final HttpStatus httpStatus;
    private final String errorCode;

    public ApiException(String message, HttpStatus httpStatus, String errorCode) {
        super(message);
        this.httpStatus = httpStatus;
        this.errorCode = errorCode;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    public String getErrorCode() {
        return errorCode;
    }
}