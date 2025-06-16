package pl.kamann.entities.event;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PostPersist;
import jakarta.persistence.PostUpdate;
import jakarta.persistence.Transient;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.dmfs.rfc5545.recur.InvalidRecurrenceRuleException;
import org.dmfs.rfc5545.recur.RecurrenceRule;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import pl.kamann.entities.appuser.AppUser;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Event {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false)

    private String title;

    private String description;

    @Column(nullable = false)
    private Integer durationMinutes;

    @Column(nullable = false)
    private LocalDateTime releaseDate;

    @Column(length = 1000)
    private String rrule;

    @Enumerated(EnumType.STRING)
    private SchedulingStatus schedulingStatus;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "created_by_id", nullable = false)
    private AppUser createdBy;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "event_type_id", nullable = false)
    private EventType eventType;

    @Column(nullable = false)
    private int maxParticipants;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "instructor_id")
    private AppUser instructor;

    @Transient
    private RecurrenceRule recurrenceRule;

    @CreationTimestamp
    @Column(updatable = false)
    LocalDateTime createdAt;

    @UpdateTimestamp
    LocalDateTime updatedAt;

    @OneToMany(mappedBy = "event", fetch = FetchType.LAZY)
    private Set<OccurrenceEvent> occurrences = new HashSet<>();

    @Enumerated(EnumType.STRING)
    @Column(name = "difficulty", nullable = false)
    private EventDifficulty eventDifficulty;

    @PostLoad
    @PostPersist
    @PostUpdate
    private void initializeRecurrenceRule() {
        if (rrule != null && !rrule.isEmpty()) {
            try {
                this.recurrenceRule = new RecurrenceRule(rrule);
            } catch (InvalidRecurrenceRuleException e) {
                throw new IllegalArgumentException("Invalid recurrence rule: " + rrule, e);
            }
        }
    }
}