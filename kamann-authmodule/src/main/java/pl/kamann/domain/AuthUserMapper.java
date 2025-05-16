package pl.kamann.domain;

import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.stream.Collectors;

@Component
public class AuthUserMapper {

    public AuthUserEntity toEntity(AuthUser domain) {
        AuthUserEntity entity = new AuthUserEntity();
        entity.setEmail(domain.getEmail().value());
        entity.setPassword(domain.getPassword().value());
        entity.setStatus(domain.getStatus());

        Set<String> roleNames = domain.getRoles().stream()
                .map(Role::name)
                .collect(Collectors.toSet());
        entity.setRoles(roleNames);

        return entity;
    }

    public AuthUser toDomain(AuthUserEntity entity) {
        Set<Role> roles = entity.getRoles().stream()
                .map(Role::fromName)
                .collect(Collectors.toSet());

        return AuthUser.restore(
                new AuthUserId(entity.getId()),
                new Email(entity.getEmail()),
                new Password(entity.getPassword()),
                roles,
                entity.getStatus()
        );
    }
}
