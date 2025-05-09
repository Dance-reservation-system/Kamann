package pl.kamann.application.shared.pagination;


import shared.dto.PaginationCriteria;

import java.io.Serializable;

public record PaginationMetaData(int totalPages, long totalElements) implements Serializable {

    public static PaginationMetaData from(PaginationCriteria criteria, long totalElements) {
        int totalPages = (int) Math.ceil((double) totalElements / criteria.getSize());
        return new PaginationMetaData(totalPages, totalElements);
    }
}