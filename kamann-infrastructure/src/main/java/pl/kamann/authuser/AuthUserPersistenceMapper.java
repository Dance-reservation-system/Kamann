package pl.kamann.authuser;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import pl.kamann.authuser.entity.AuthUserEntity;
import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.vo.AuthUserId;
import pl.kamann.domain.authuser.vo.Email;

import java.util.UUID;

@Mapper(componentModel = "spring")
public interface AuthUserPersistenceMapper {

    @Mapping(source = "email", target = "email")
    AuthUser toDomain(AuthUserEntity entity);

    default Email map(String email) {
        return new Email(email);
    }

    default AuthUserId map(UUID value) {
        return new AuthUserId(value);
    }

}