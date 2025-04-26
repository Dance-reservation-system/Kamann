package pl.kamann.domain.appuser.repository;

import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.authuser.AuthUser;

import java.util.Optional;

public interface AppUserRepository {

    Optional<AppUser> findById(Long id);

    Optional<AppUser> findByAuthUser(AuthUser authUser);

    Optional<AppUser> findByAuthUser_Email_Value(String email);

    AppUser save(AppUser appUser);

    void delete(AppUser appUser);

}