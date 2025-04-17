package pl.kamann.infrastructure.repository.authuser;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import pl.kamann.domain.common.PaginationCriteria;
import pl.kamann.domain.appuser.Role;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.AuthUserRepository;

import java.util.List;
import java.util.Optional;

@Repository
interface JpaAuthUserRepository extends JpaRepository<AuthUser, Long>, AuthUserRepository {

    @Override
    Optional<AuthUser> findByEmail(String email);

    @Override
    @Query("SELECT u FROM AuthUser u JOIN u.roles r WHERE r.name = 'ADMIN'")
    List<AuthUser> findAdminUser();

    @Query("SELECT u FROM AuthUser u JOIN u.roles r WHERE r = :role")
    Page<AuthUser> findUsersByRoleWithRoles(Pageable pageable, @Param("role") Role role);

    @Query("SELECT u FROM AuthUser u JOIN u.roles r WHERE r = :role")
    Page<AuthUser> findByRolesContaining(Role role, Pageable pageable);

    @Override
    boolean existsByEmail(String email);

    @Override
    default List<AuthUser> findAll(PaginationCriteria criteria) {
        Pageable pageable = criteria.toSpringPageable();
        Page<AuthUser> page = findAll(pageable);
        return page.getContent();
    }

    @Override
    default List<AuthUser> findUsersByRoleWithRoles(Role role, PaginationCriteria criteria) {
        Pageable pageable = criteria.toSpringPageable();
        Page<AuthUser> page = findUsersByRoleWithRoles(pageable, role);
        return page.getContent();
    }

    @Override
    default List<AuthUser> findByRolesContaining(Role role, PaginationCriteria criteria) {
        Pageable pageable = criteria.toSpringPageable();
        Page<AuthUser> page = findByRolesContaining(role, pageable);
        return page.getContent();
    }
}