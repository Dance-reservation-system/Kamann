package pl.kamann.authuser;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.vo.Email;

@Mapper(componentModel = "spring")
public interface AuthUserPersistenceMapper {

    @Mapping(source = "email", target = "email")
    AuthUser toDomain(AuthUser entity);

    default Email map(String email) {
        return new Email(email);
    }
}