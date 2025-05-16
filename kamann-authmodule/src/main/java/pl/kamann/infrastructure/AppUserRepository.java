package pl.kamann.infrastructure;

import pl.kamann.application.AppUserId;
import pl.kamann.domain.AppUser;
import pl.kamann.domain.AuthUser;

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
