package pl.kamann.services.admin.update;

import java.time.LocalDateTime;

public record UpdateCriteria(LocalDateTime startAfter, LocalDateTime endBefore) {
}
