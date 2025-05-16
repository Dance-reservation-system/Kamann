package pl.kamann.infrastructure;

import pl.kamann.domain.AuthUser;
import pl.kamann.domain.Email;
import pl.kamann.domain.Role;

import java.util.List;
import java.util.Optional;

public interface AuthUserRepository {
    Optional<AuthUser> findByEmail(Email email);
    List<AuthUser> findByRole(Role role);
    void save(AuthUser user);
    void delete(AuthUser authUser);
}