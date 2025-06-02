package pl.kamann.domain.repository;

import pl.kamann.domain.entity.AuthUser;
import pl.kamann.domain.vo.Email;
import pl.kamann.domain.vo.Role;

import java.util.List;
import java.util.Optional;

public interface AuthUserRepository {
    Optional<AuthUser> findByEmail(Email email);
    List<AuthUser> findByRole(Role role);
    void save(AuthUser user);
    void delete(AuthUser authUser);
}