package pl.kamann.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import pl.kamann.dtos.UserDetailsDto;
import pl.kamann.entities.appuser.AppUser;
import pl.kamann.entities.appuser.AuthUser;

public interface AccountRepository extends JpaRepository<AppUser, Long> {

//    UserDetailsDto updateUserAccountDetails(UserDetailsDto requestDto, AppUser appUser, AuthUser authUser);
}
