package pl.kamann.infrastructure.repository.appuser;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.appuser.repository.AppUserRepository;

import java.util.Optional;

@Repository
interface JpaAppUserRepository extends JpaRepository<AppUser, Long>, AppUserRepository {

    @Transactional(readOnly = true)
    Optional<AppUser> findByAuthUserId(Long authUserId);

    @Transactional(readOnly = true)
    boolean existsByAuthUserId(Long authUserId);

    @Transactional(readOnly = true)
    Page<AppUser> findAll(Pageable pageable);
}