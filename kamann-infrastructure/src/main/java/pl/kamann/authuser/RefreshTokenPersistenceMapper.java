package pl.kamann.authuser;

import org.springframework.stereotype.Component;
import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.entity.RefreshToken;
import pl.kamann.domain.authuser.entity.RefreshTokenJpaEntity;
import pl.kamann.domain.authuser.vo.AuthUserId;
import pl.kamann.domain.authuser.vo.RefreshTokenId;
import pl.kamann.domain.authuser.vo.TokenType;

@Component
public class RefreshTokenPersistenceMapper {

    public RefreshTokenJpaEntity toJpaEntity(RefreshToken domain) {
        var entity = new RefreshTokenJpaEntity();
        if (domain.getId() != null) {
            entity.setId(domain.getId().value());
        }
        entity.setAuthUserId(domain.getUserId().getValue());
        entity.setToken(domain.getToken());
        entity.setExpiresAt(domain.getExpiresAt());
        entity.setType(domain.getType().name());
        return entity;
    }

    public RefreshToken toDomain(RefreshTokenJpaEntity entity, AuthUser user) {
        return RefreshToken.of(
                new RefreshTokenId(entity.getId()),
                new AuthUserId(entity.getAuthUserId()),
                entity.getToken(),
                entity.getExpiresAt(),
                TokenType.valueOf(entity.getType()),
                user
        );
    }
}