package pl.kamann.infrastructure.authuser;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.entity.RefreshToken;
import pl.kamann.domain.authuser.port.out.RefreshTokenRepository;
import pl.kamann.domain.authuser.service.RefreshTokenService;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    public RefreshToken issue(AuthUser user) {


        return RefreshToken.of(null, null, null, null, null, user);
    }

    @Override
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Override
    public void revoke(RefreshToken token) {
        refreshTokenRepository.delete(token);
    }
}
