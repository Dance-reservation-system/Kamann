package pl.kamann.authuser.repository;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import pl.kamann.appuser.AppUserMapper;
import pl.kamann.appuser.entity.AppUserEntity;
import pl.kamann.appuser.repository.JpaAppUserRepository;
import pl.kamann.domain.appuser.aggregate.AppUser;
import pl.kamann.domain.appuser.repository.AppUserRepository;
import pl.kamann.domain.appuser.vo.AppUserId;
import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.vo.Email;

import java.util.Optional;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
public class AppUserRepositoryImpl implements AppUserRepository {

    private final JpaAppUserRepository jpaAppUserRepository;
    private final AppUserMapper mapper;

        public Optional<AppUser> findByEmail(Email email) {
        return jpaAppUserRepository.findByEmail(email.value())
                .map(mapper::toDomain);
    }

    @Override
    public Optional<AppUser> findById(AppUserId id) {
        return jpaAppUserRepository.findById(id.getValue())
                .map(mapper::toDomain);
    }

    @Override
    public void save(AppUser user) {
        AppUserEntity entity = mapper.toEntity(user);
        jpaAppUserRepository.save(entity);
    }

    @Override
    public Optional<AppUser> findByAuthUser(AuthUser authUser) {
        UUID authUserId = authUser.getId().getValue();
        return jpaAppUserRepository.findByAuthUserId(authUserId)
                .map(mapper::toDomain);
    }

    @Override
    public Optional<AppUser> findByAuthUser_Email_Value(String email) {
        return jpaAppUserRepository.findByEmail(email)
                .map(mapper::toDomain);
    }

    @Override
    public Optional<AppUser> findByIdWithAuth(UUID id) {
        return jpaAppUserRepository.findByIdWithAuthUser(id)
                .map(mapper::toDomain);
    }
}
