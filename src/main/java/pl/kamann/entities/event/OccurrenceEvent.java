package pl.kamann.entities.event;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import pl.kamann.dtos.OccurrenceEventScope;
import pl.kamann.entities.appuser.AppUser;
import pl.kamann.entities.attendance.Attendance;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(indexes = {
        @Index(name = "idx_occurrence_event", columnList = "event_id, meeting_date"),
        @Index(name = "idx_occurrence_meeting_date", columnList = "meeting_date")
})
public class OccurrenceEvent implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "event_id", nullable = false)
    private Event event;

    @Column(name = "meeting_date", nullable = false)
    private LocalDateTime meetingDate;

    @Column(nullable = false)
    private OccurrenceEventStatus occurrenceEventStatus;

    @Transient
    private AppUser createdBy;

    @Column(nullable = false)
    private int seriesIndex;

    @Enumerated(EnumType.STRING)
    private OccurrenceEventScope scope;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "instructor_id")
    private AppUser instructor;

    @OneToMany(fetch = FetchType.EAGER, mappedBy = "occurrenceEvent", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<Attendance> attendances = new HashSet<>();

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "occurrence_event_participants", joinColumns = @JoinColumn(name = "occurrence_event_id"), inverseJoinColumns = @JoinColumn(name = "app_user_id"))
    private Set<AppUser> participants = new HashSet<>();

    public LocalDateTime getEnd() {
        return meetingDate.plusMinutes(event.getDurationMinutes());
    }
}
