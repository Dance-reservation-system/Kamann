package pl.kamann.infrastructure.pagination;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;
import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class PaginatedResponseDto<T> implements Serializable {
    private List<T> content;
    private PaginationMetaData metaData;
}
