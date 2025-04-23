package pl.kamann.domain.event;

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
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.attendance.Attendance;
import pl.kamann.domain.event.dto.OccurrenceEventScope;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Getter
@NoArgsConstructor
@Table(indexes = {
        @Index(name = "idx_occurrence_event", columnList = "event_id,start"),
        @Index(name = "idx_occurrence_start", columnList = "start")
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

    @Column(nullable = false)
    private LocalDateTime start;

    @Column(nullable = false)
    private Integer durationMinutes;

    private boolean canceled;

    private boolean excluded;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "created_by", nullable = false)
    private AppUser createdBy;

    private int maxParticipants;

    @Enumerated(EnumType.STRING)
    private EventStatus eventStatus;

    @Column(nullable = false)
    private int seriesIndex;

    @Enumerated(EnumType.STRING)
    private OccurrenceEventScope scope;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "instructor_id")
    private AppUser instructor;

    @OneToMany(fetch = FetchType.LAZY, mappedBy = "occurrenceEvent", cascade = CascadeType.ALL, orphanRemoval = true)
    private final Set<Attendance> attendances = new HashSet<>();

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "occurrence_event_participants",
            joinColumns = @JoinColumn(name = "occurrence_event_id"),
            inverseJoinColumns = @JoinColumn(name = "app_user_id")
    )
    private final Set<AppUser> participants = new HashSet<>();

    public static OccurrenceEvent create(Event event, LocalDateTime start, AppUser createdBy) {
        OccurrenceEvent o = new OccurrenceEvent();
        o.event = event;
        o.start = start;
        o.durationMinutes = event.getDurationMinutes();
        o.maxParticipants = event.getMaxParticipants();
        o.instructor = event.getInstructor();
        o.createdBy = createdBy;
        o.seriesIndex = 0;
        o.eventStatus = EventStatus.SCHEDULED;
        o.scope = OccurrenceEventScope.PUBLIC;
        return o;
    }

    public LocalDateTime getEnd() {
        return start.plusMinutes(durationMinutes);
    }

    public boolean isModified() {
        return !start.equals(event.getStart()) ||
                !durationMinutes.equals(event.getDurationMinutes()) ||
                canceled ||
                excluded ||
                (instructor != null && !instructor.equals(event.getInstructor()));
    }

    public void registerParticipant(AppUser participant) {
        participants.add(participant);
    }

    public void cancel() {
        this.canceled = true;
        this.eventStatus = EventStatus.CANCELED;
    }

    public void exclude() {
        this.excluded = true;
    }

    public boolean hasCapacity() {
        return this.participants.size() < this.maxParticipants;
    }

    public boolean isActive() {
        return !canceled && !excluded && LocalDateTime.now().isBefore(getEnd());
    }

    @PrePersist
    @PreUpdate
    private void setDefaults() {
        if (durationMinutes == null) {
            durationMinutes = event.getDurationMinutes();
        }
        if (maxParticipants == 0) {
            maxParticipants = event.getMaxParticipants();
        }
        if (instructor == null) {
            instructor = event.getInstructor();
        }
    }

    public void setSeriesIndex(int seriesIndex) {
        this.seriesIndex = seriesIndex;
    }
}
