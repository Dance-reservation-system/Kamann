package pl.kamann.domain.authuser;

import pl.kamann.domain.common.PaginationCriteria;
import pl.kamann.domain.appuser.Role;

import java.util.List;
import java.util.Optional;

public interface AuthUserRepository {

    Optional<AuthUser> findById(Long id);

    Optional<AuthUser> findByEmail(String email);

    List<AuthUser> findAll();

    List<AuthUser> findAll(PaginationCriteria criteria);

    void save(AuthUser authUser);

    void delete(AuthUser authUser);

    boolean existsByEmail(String email);

    List<AuthUser> findAdminUser();

    List<AuthUser> findUsersByRoleWithRoles(Role role, PaginationCriteria criteria);

    List<AuthUser> findByRolesContaining(Role role, PaginationCriteria criteria);
}