package pl.kamann.config.exception.specific;

import org.springframework.http.HttpStatus;
import pl.kamann.config.exception.handler.ApiException;

public class IllegalDateRangeException extends ApiException {
    public IllegalDateRangeException(String message, HttpStatus status, String code) {
        super(message, status, code);
    }
}
