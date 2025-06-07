package pl.kamann.authuser;

import pl.kamann.authuser.entity.AuthUserEntity;
import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.vo.AuthUserId;
import pl.kamann.domain.authuser.vo.Email;

public interface AuthUserPersistenceMapper {

    AuthUser toDomain(AuthUserEntity entity);

    default Email map(String email) {
        return new Email(email);
    }

    default AuthUserId map(Long value) {
        return new AuthUserId(value);
    }

}