package pl.kamann.infrastructure.pagination;

import pl.kamann.domain.common.PaginationCriteria;

import java.io.Serializable;

public record PaginationMetaData(int totalPages, long totalElements) implements Serializable {

    public static PaginationMetaData from(PaginationCriteria criteria, long totalElements) {
        int totalPages = (int) Math.ceil((double) totalElements / criteria.size());
        return new PaginationMetaData(totalPages, totalElements);
    }
}