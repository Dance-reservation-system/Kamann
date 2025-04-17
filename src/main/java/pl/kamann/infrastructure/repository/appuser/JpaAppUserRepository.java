package pl.kamann.infrastructure.repository.appuser;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import pl.kamann.domain.common.PaginationCriteria;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.appuser.AppUserRepository;

import java.util.List;
import java.util.Optional;

@Repository
interface JpaAppUserRepository extends JpaRepository<AppUser, Long>, AppUserRepository {

    Optional<AppUser> findByAuthUserId(Long authUserId);

    Optional<AppUser> findByAuthUser_Email(String email);

    boolean existsByAuthUserId(Long authUserId);

    Page<AppUser> findAll(Pageable pageable);

    Page<AppUser> findByRolesContaining(String roleName, Pageable pageable);

    @Override
    default List<AppUser> findAll(PaginationCriteria criteria) {
        Pageable pageable = criteria.toSpringPageable();
        Page<AppUser> page = findAll(pageable);
        return page.getContent();
    }

    @Override
    default List<AppUser> findByRolesContaining(String roleName, PaginationCriteria criteria) {
        Pageable pageable = criteria.toSpringPageable();
        Page<AppUser> page = findByRolesContaining(roleName, pageable);
        return page.getContent();
    }
}