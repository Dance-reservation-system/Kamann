package pl.kamann.domain.authuser.port.out;

import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.vo.Email;
import pl.kamann.domain.authuser.vo.Role;
import shared.dto.PaginationCriteria;

import java.util.List;
import java.util.Optional;

/**
 * Domain port for loading and saving AuthUser aggregates.
 * No framework or pagination types here.
 */
public interface AuthUserRepository {
    Optional<AuthUser> findByEmail(Email email);
    void save(AuthUser user);
    void delete(AuthUser user);

    List<AuthUser> findByRole(Role admin);

    List<AuthUser> findAll(PaginationCriteria criteria);
    long count();
    List<AuthUser> findByRolesContaining(Role role, PaginationCriteria criteria);
    long countByRole(Role role);
}
