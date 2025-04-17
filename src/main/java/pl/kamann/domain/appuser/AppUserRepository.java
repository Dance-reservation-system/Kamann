package pl.kamann.domain.appuser;

import pl.kamann.domain.common.PaginationCriteria;

import java.util.List;
import java.util.Optional;

public interface AppUserRepository {

    Optional<AppUser> findById(Long id);

    Optional<AppUser> findByAuthUserId(Long authUserId);

    Optional<AppUser> findByEmail(String email);

    List<AppUser> findAll();

    List<AppUser> findAll(PaginationCriteria criteria);
    void save(AppUser appUser);

    void delete(AppUser appUser);

    boolean existsByAuthUserId(Long authUserId);

    List<AppUser> findByRolesContaining(String roleName, PaginationCriteria criteria);
}