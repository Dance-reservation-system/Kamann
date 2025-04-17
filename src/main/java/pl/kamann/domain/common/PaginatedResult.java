package pl.kamann.domain.common;

import java.util.List;

interface PaginatedResult<T> {
    List<T> getContent();
    long getTotalElements();
    int getTotalPages();
}