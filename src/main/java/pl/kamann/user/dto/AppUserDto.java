package pl.kamann.user.dto;

import lombok.Builder;
import lombok.Data;
import pl.kamann.auth.role.model.Role;

import java.time.LocalDate;
import java.util.Set;

@Data
@Builder
public class AppUserDto {
    private Long id;
    private String email;
    private String firstName;
    private String lastName;
    private Set<Role> roles;
    private LocalDate cardExpiryDate;
}