package pl.kamann.application.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import pl.kamann.domain.authuser.AuthUserRepository;

@Service("userDetailsService")
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final AuthUserRepository authUserRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return authUserRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("Nie znaleziono użytkownika o emailu: " + username));
    }
}