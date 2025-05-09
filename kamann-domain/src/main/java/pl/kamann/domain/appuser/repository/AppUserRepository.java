package pl.kamann.domain.appuser.repository;

import pl.kamann.domain.appuser.aggregate.AppUser;
import pl.kamann.domain.appuser.vo.AppUserId;
import pl.kamann.domain.authuser.aggregate.AuthUser;

import java.util.Optional;

/**
 * Port for loading/saving AppUser aggregates.
 */
public interface AppUserRepository {
    Optional<AppUser> findById(AppUserId id);
    void save(AppUser user);
    Optional<AppUser> findByAuthUser(AuthUser authUser);

    Optional<AppUser> findByAuthUser_Email_Value(String email);

    Optional<AppUser> findByIdWithAuth(Long id);
}
