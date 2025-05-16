package pl.kamann.infrastructure;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import pl.kamann.domain.AuthUserEntity;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "app_users")
@Getter
@Setter
public class AppUserEntity {

    @Id
    @GeneratedValue
    private UUID id;

    @OneToOne(cascade = CascadeType.PERSIST)
    @JoinColumn(name = "auth_user_id")
    private AuthUserEntity authUser;


    private String firstName;
    private String lastName;
    private String phone;

    private Instant createdAt;
    private Instant updatedAt;
}
