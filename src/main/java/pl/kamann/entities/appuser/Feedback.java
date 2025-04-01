package pl.kamann.entities.appuser;

import jakarta.persistence.*;
import lombok.Data;
import pl.kamann.entities.event.OccurrenceEvent;

@Data
@Entity
public class Feedback {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 1000)
    private String coachOpinion;
    private int coachRating;

    @Column(length = 1000)
    private String classesOpinion;
    private int classesRating;

    @Transient
    private Long occurrenceEventId;

    @OneToOne
    private OccurrenceEvent occurrenceEvent;
}