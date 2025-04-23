package pl.kamann.domain.common;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

public record PaginationCriteria(int page, int size) {
    public static final int DEFAULT_PAGE = 0;
    public static final int DEFAULT_SIZE = 20;
    public static final int MAX_SIZE = 100;

    public PaginationCriteria(int page, int size) {
        this.page = Math.max(DEFAULT_PAGE, page);
        this.size = Math.clamp(size, 1, MAX_SIZE);
    }

    public PaginationCriteria(Pageable pageable) {
        this(pageable.getPageNumber(), pageable.getPageSize());
    }

    public Pageable toSpringPageable() {
        return PageRequest.of(this.page, this.size);
    }
}