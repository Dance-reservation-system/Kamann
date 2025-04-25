package pl.kamann.domain.appuser.repository;

import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.authuser.AuthUser;

import java.util.List;
import java.util.Optional;

public interface AppUserRepository {

    void saveAll(List<AppUser> appUsers);

    Optional<AppUser> findById(Long id);

    Optional<AppUser> findByAuthUser(AuthUser authUser);

    Optional<AppUser> findByEmail(String email);

    AppUser save(AppUser appUser);

    void delete(AppUser appUser);

}