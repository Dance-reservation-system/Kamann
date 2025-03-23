package pl.kamann.entities.appuser;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column(nullable = false)
    private String token;

    @Column(nullable = false)
    private LocalDateTime expirationTime;

    @ManyToOne
    @JoinColumn(name = "auth_user_id", nullable = false)
    private AuthUser authUser;
}
