package pl.kamann.authuser.mapper;

import org.springframework.stereotype.Component;
import pl.kamann.authuser.entity.AuthUserEntity;
import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.vo.AuthUserId;
import pl.kamann.domain.authuser.vo.Email;
import pl.kamann.domain.authuser.vo.Password;

@Component
public class AuthUserPersistenceMapper {

    public AuthUser toDomain(AuthUserEntity entity) {
        return AuthUser.restore(
            new AuthUserId(entity.getId()),
            new Email(entity.getEmail()),
            new Password(entity.getPassword()),
            entity.getRoles(),
            entity.getStatus()
        );
    }

    public AuthUserEntity toEntity(AuthUser domain) {
        AuthUserEntity entity = new AuthUserEntity();
        entity.setId(domain.getId().getValue());
        entity.setEmail(domain.getEmail().value());
        entity.setPassword(domain.getPassword().value());
        entity.setRoles(domain.getRoles());
        entity.setStatus(domain.getStatus());
        return entity;
    }
}
