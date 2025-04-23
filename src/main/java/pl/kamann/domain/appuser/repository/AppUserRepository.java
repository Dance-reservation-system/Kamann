package pl.kamann.domain.appuser.repository;

import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.appuser.Role;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.common.PaginationCriteria;

import java.util.List;
import java.util.Optional;

public interface AppUserRepository {

    void saveAll(List<AppUser> appUsers);

    Optional<AppUser> findById(Long id);

    Optional<AppUser> findByAuthUser(AuthUser authUser);

    Optional<AppUser> findByEmail(String email);

    List<AppUser> findAll();

    List<AppUser> findAll(PaginationCriteria criteria);

    AppUser save(AppUser appUser);

    void delete(AppUser appUser);

    boolean existsByAuthUser(AuthUser authUser);

    List<AppUser> findByRolesContaining(Role role, PaginationCriteria criteria);
}