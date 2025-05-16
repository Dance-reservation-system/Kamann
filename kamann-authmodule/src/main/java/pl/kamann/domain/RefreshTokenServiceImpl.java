package pl.kamann.domain;

import org.springframework.stereotype.Service;
import pl.kamann.application.RefreshToken;

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