package pl.kamann.infrastructure.pagination;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class PaginationMetaData implements Serializable {
    private int totalPages;
    private long totalElements;
}
