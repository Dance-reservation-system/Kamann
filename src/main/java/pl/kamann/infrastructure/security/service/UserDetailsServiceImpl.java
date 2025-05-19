package pl.kamann.infrastructure.security.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import pl.kamann.domain.entity.AuthUser;
import pl.kamann.domain.repository.AuthUserRepository;
import pl.kamann.domain.vo.Email;
import pl.kamann.infrastructure.security.adapter.AuthUserAdapter;

@Service
@RequiredArgsConstructor
class UserDetailsServiceImpl implements UserDetailsService {

    private final AuthUserRepository authUserRepository;

    @Override
    public UserDetails loadUserByUsername(String emailValue) throws UsernameNotFoundException {
        Email email = new Email(emailValue);
        AuthUser authUser = authUserRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User with mail: " + emailValue + " was not found."));
        return new AuthUserAdapter(authUser);
    }
}