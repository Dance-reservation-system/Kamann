package pl.kamann.authuser.entity;

import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import pl.kamann.authuser.entity.converter.RoleSetConverter;
import pl.kamann.domain.authuser.vo.AuthUserStatus;
import pl.kamann.domain.authuser.vo.Role;

import java.util.Set;

@Entity
@Table(name = "auth_users")
@Getter
@Setter
@NoArgsConstructor
public class AuthUserEntity {

    @Id
    @GeneratedValue(generator = "Long")
    private Long id;

    private String email;

    private String password;

    @Convert(converter = RoleSetConverter.class)
    private Set<Role> roles;

    @Enumerated(EnumType.STRING)
    private AuthUserStatus status;
}