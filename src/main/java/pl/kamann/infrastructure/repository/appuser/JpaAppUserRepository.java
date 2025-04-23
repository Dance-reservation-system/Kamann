package pl.kamann.infrastructure.repository.appuser;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.domain.appuser.Role;
import pl.kamann.domain.common.PaginationCriteria;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.appuser.repository.AppUserRepository;

import java.util.List;
import java.util.Optional;

@Repository
interface JpaAppUserRepository extends JpaRepository<AppUser, Long>, AppUserRepository {

    @Transactional(readOnly = true)
    Optional<AppUser> findByAuthUserId(Long authUserId);

    @Transactional(readOnly = true)
    boolean existsByAuthUserId(Long authUserId);

    @Transactional(readOnly = true)
    Page<AppUser> findAll(Pageable pageable);

    @Transactional(readOnly = true)
    Page<AppUser> findByRolesContaining(Role role, Pageable pageable);

    @Override
    default List<AppUser> findAll(PaginationCriteria criteria) {
        Pageable pageable = criteria.toSpringPageable();
        Page<AppUser> page = findAll(pageable);
        return page.getContent();
    }

    @Override
    default List<AppUser> findByRolesContaining(Role role, PaginationCriteria criteria) {
        Pageable pageable = criteria.toSpringPageable();
        Page<AppUser> page = findByRolesContaining(role, pageable);
        return page.getContent();
    }
}