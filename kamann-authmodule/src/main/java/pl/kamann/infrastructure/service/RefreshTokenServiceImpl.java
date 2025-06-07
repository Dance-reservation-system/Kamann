package pl.kamann.infrastructure.service;

import org.springframework.stereotype.Service;
import pl.kamann.domain.entity.AuthUser;
import pl.kamann.domain.entity.RefreshToken;
import pl.kamann.domain.service.RefreshTokenService;

import java.util.Optional;

@Service
public class RefreshTokenServiceImpl implements RefreshTokenService {


    @Override
    public RefreshToken issue(AuthUser user) {
        return null;
    }

    @Override
    public Optional<RefreshToken> findByToken(String token) {
        return Optional.empty();
    }

    @Override
    public void revoke(RefreshToken token) {

    }
}