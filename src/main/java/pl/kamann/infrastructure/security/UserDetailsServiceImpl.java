package pl.kamann.infrastructure.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.AuthUserRepository;

@Service
@RequiredArgsConstructor
class UserDetailsServiceImpl implements UserDetailsService {

    private final AuthUserRepository authUserRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        AuthUser authUser = authUserRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User with mail: " + email + " was not found."));
        return new AuthUserAdapter(authUser);
    }
}