package pl.kamann.domain.attendance;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import lombok.Getter;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.event.OccurrenceEvent;

import java.time.LocalDateTime;

@Entity
@Getter
public class Attendance {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private AppUser user;

    @ManyToOne(optional = false)
    @JoinColumn(name = "occurrence_event_id", nullable = false)
    private OccurrenceEvent occurrenceEvent;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AttendanceStatus status;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    protected Attendance() {
    }

    public static Attendance create(AppUser user, OccurrenceEvent event) {
        Attendance attendance = new Attendance();
        attendance.user = user;
        attendance.occurrenceEvent = event;
        attendance.status = AttendanceStatus.REGISTERED;
        attendance.timestamp = LocalDateTime.now();
        return attendance;
    }

    public void cancelWithStatus(AttendanceStatus status) {
        this.status = status;
    }

    public void overrideStatus(AttendanceStatus status) {
        this.status = status;
    }
}
