package pl.kamann.config.codes;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum EventCodes {
    EVENT_NOT_FOUND("EVENT_NOT_FOUND"),
    PAST_EVENT_ERROR("PAST_EVENT_ERROR"),
    EVENT_TYPE_NOT_FOUND("EVENT_TYPE_NOT_FOUND"),
    INVALID_EVENT_TIME("INVALID_EVENT_TIME"),
    EVENT_HAS_OCCURRENCES("EVENT_HAS_OCCURRENCES"),
    OCCURRENCE_GENERATION_FAILED("OCCURRENCE_GENERATION_FAILED"),
    OCCURRENCE_NOT_FOUND("OCCURRENCE_NOT_FOUND"),
    INVALID_MAX_PARTICIPANTS("INVALID_MAX_PARTICIPANTS"),
    INVALID_EVENT_DURATION("INVALID_EVENT_DURATION"),
    INVALID_EVENT_START("INVALID_EVENT_START"),
    INVALID_EVENT_DESCRIPTION("INVALID_EVENT_DESCRIPTION"),
    INVALID_EVENT_TITLE("INVALID_EVENT_TITLE"),
    EVENT_ALREADY_CANCELED("EVENT_ALREADY_CANCELED"),
    INVALID_EVENT_START_UPDATE("INVALID_EVENT_START_UPDATE"),
    EVENT_ALREADY_CANCELLED("EVENT_ALREADY_CANCELLED");

    private final String code;
}
