package pl.kamann.infrastructure;

import org.springframework.stereotype.Component;
import pl.kamann.domain.AuthUser;
import pl.kamann.domain.AuthUserEntity;
import pl.kamann.domain.AuthUserId;
import pl.kamann.domain.Email;
import pl.kamann.domain.Password;
import pl.kamann.domain.Role;

import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class AuthUserPersistenceMapperImpl implements AuthUserPersistenceMapper {

    @Override
    public AuthUser toDomain(AuthUserEntity entity) {
        return AuthUser.restore(
                new AuthUserId(entity.getId()),
                new Email(entity.getEmail()),
                new Password(entity.getPassword()),
                entity.getRoles().stream()
                        .map(Role::fromName)
                        .collect(Collectors.toSet()),
                entity.getStatus()
        );
    }

    @Override
    public Email map(String email) {
        return new Email(email);
    }

    @Override
    public AuthUserId map(UUID value) {
        return new AuthUserId(value);
    }

    @Override
    public AuthUserEntity toEntity(AuthUser domain) {
        AuthUserEntity entity = new AuthUserEntity();

        if (domain.getId() != null && domain.getId().getValue() != null) {
            entity.setId(domain.getId().getValue());
        }

        entity.setEmail(domain.getEmail().value());
        entity.setPassword(domain.getPassword().value());
        entity.setStatus(domain.getStatus());
        entity.setRoles(domain.getRoles().stream().map(Role::name).collect(Collectors.toSet()));

        return entity;
    }
}