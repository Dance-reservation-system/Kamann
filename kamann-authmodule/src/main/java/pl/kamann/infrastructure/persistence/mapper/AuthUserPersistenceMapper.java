package pl.kamann.infrastructure.persistence.mapper;


import pl.kamann.domain.entity.AuthUser;
import pl.kamann.infrastructure.persistence.jpa.AuthUserEntity;
import pl.kamann.domain.vo.AuthUserId;
import pl.kamann.domain.vo.Email;
import pl.kamann.domain.vo.Role;

import java.util.UUID;
import java.util.stream.Collectors;

public interface AuthUserPersistenceMapper {

    AuthUser toDomain(AuthUserEntity entity);

    default Email map(String email) {
        return new Email(email);
    }

    default AuthUserId map(UUID value) {
        return new AuthUserId(value);
    }

    default AuthUserEntity toEntity(AuthUser domain) {
        AuthUserEntity entity = new AuthUserEntity();
        entity.setId(domain.getId().getValue());
        entity.setEmail(domain.getEmail().value());
        entity.setPassword(domain.getPassword().value());
        entity.setStatus(domain.getStatus());
        entity.setRoles(domain.getRoles().stream().map(Role::name).collect(Collectors.toSet()));
        return entity;
    }

}