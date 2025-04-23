package pl.kamann.infrastructure.repository.authuser;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import pl.kamann.domain.appuser.Role;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.Email;

import java.util.List;
import java.util.Optional;

public interface JpaAuthUserRepository extends JpaRepository<AuthUser, Long> {
    Optional<AuthUser> findByEmail(Email email);

    @Query("SELECT u FROM AuthUser u JOIN u.roles r WHERE r = :role")
    Page<AuthUser> findByRolesContaining(@Param("role") Role role, Pageable pageable);

    @Query("SELECT COUNT(u) FROM AuthUser u JOIN u.roles r WHERE r = :role")
    long countByRole(@Param("role") Role role);

    @Query("SELECT u FROM AuthUser u JOIN u.roles r WHERE r.name = 'ADMIN'")
    List<AuthUser> findAdminUser();

    boolean existsByEmail(Email email);
}