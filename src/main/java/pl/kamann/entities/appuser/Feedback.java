package pl.kamann.entities.appuser;

import jakarta.persistence.*;
import lombok.Data;

@Data
@Entity
public class Feedback {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 1000)
    private String coachOpinion;

    @Column(length = 1000)
    private String classesOpinion;
}
