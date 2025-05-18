package pl.kamann.domain.repository;

import pl.kamann.domain.vo.AppUserId;
import pl.kamann.domain.entity.AppUser;
import pl.kamann.domain.entity.AuthUser;

import java.util.Optional;
import java.util.UUID;

/**
 * Port for loading/saving AppUser aggregates.
 */
public interface AppUserRepository {
    Optional<AppUser> findById(AppUserId id);
    void save(AppUser user);
    Optional<AppUser> findByAuthUser(AuthUser authUser);

    Optional<AppUser> findByAuthUser_Email_Value(String email);

    Optional<AppUser> findByIdWithAuth(UUID id);
}
