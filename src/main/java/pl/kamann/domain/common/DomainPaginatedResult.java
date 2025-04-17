package pl.kamann.domain.common;

import java.util.List;

record DomainPaginatedResult<T>(List<T> content, long totalElements,
                                       int totalPages) implements PaginatedResult<T> {
    @Override
    public List<T> getContent() {
        return content;
    }

    @Override
    public long getTotalElements() {
        return totalElements;
    }

    @Override
    public int getTotalPages() {
        return totalPages;
    }
}