package pl.kamann.domain.authuser;

import pl.kamann.domain.appuser.Role;
import pl.kamann.domain.common.PaginationCriteria;

import java.util.List;
import java.util.Optional;

public interface AuthUserRepository {
    Optional<AuthUser> findByEmail(Email email);
    Optional<AuthUser> findById(Long id);
    boolean existsByEmail(Email email);
    List<AuthUser> findAll(PaginationCriteria criteria);
    long countByRole(Role role);
    long count();
    void save(AuthUser user);
    void delete(AuthUser user);
    List<AuthUser> findAdminUser();
    List<AuthUser> findByRolesContaining(Role role, PaginationCriteria criteria);
}