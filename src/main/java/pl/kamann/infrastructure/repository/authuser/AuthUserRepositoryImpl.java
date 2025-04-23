package pl.kamann.infrastructure.repository.authuser;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import pl.kamann.domain.appuser.Role;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.AuthUserRepository;
import pl.kamann.domain.authuser.Email;
import pl.kamann.domain.common.PaginationCriteria;

import java.util.List;
import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class AuthUserRepositoryImpl implements AuthUserRepository {

    private final JpaAuthUserRepository jpa;

    @Override
    public Optional<AuthUser> findById(Long id) {
        return jpa.findById(id);
    }

    @Override
    public Optional<AuthUser> findByEmail(Email email) {
        return jpa.findByEmail(email);
    }

    @Override
    public boolean existsByEmail(Email email) {
        return jpa.existsByEmail(email);
    }

    @Override
    public List<AuthUser> findAll(PaginationCriteria criteria) {
        return jpa.findAll(criteria.toSpringPageable()).getContent();
    }

    @Override
    public long countByRole(Role role) {
        return jpa.countByRole(role);
    }

    @Override
    public long count() {
        return jpa.count();
    }

    @Override
    public void save(AuthUser user) {
        jpa.save(user);
    }

    @Override
    public void delete(AuthUser user) {
        jpa.delete(user);
    }

    @Override
    public List<AuthUser> findAdminUser() {
        return jpa.findAdminUser();
    }

    @Override
    public List<AuthUser> findByRolesContaining(Role role, PaginationCriteria criteria) {
        return jpa.findByRolesContaining(role, criteria.toSpringPageable()).getContent();
    }
}