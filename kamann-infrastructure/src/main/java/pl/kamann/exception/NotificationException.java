package pl.kamann.exception;

public class NotificationException extends RuntimeException {
    public NotificationException(String message, Throwable cause) {
        super(message, cause);
    }
}