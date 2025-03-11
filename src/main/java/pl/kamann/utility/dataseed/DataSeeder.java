package pl.kamann.utility.dataseed;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.entities.appuser.AppUser;
import pl.kamann.entities.appuser.AuthUser;
import pl.kamann.entities.appuser.AuthUserStatus;
import pl.kamann.entities.appuser.Role;
import pl.kamann.entities.attendance.Attendance;
import pl.kamann.entities.attendance.AttendanceStatus;
import pl.kamann.entities.event.Event;
import pl.kamann.entities.event.EventStatus;
import pl.kamann.entities.event.EventType;
import pl.kamann.entities.event.OccurrenceEvent;
import pl.kamann.repositories.*;
import pl.kamann.services.admin.AdminEventService;
import pl.kamann.utility.EntityLookupService;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.IntStream;

@Service
@RequiredArgsConstructor
@ConditionalOnProperty(name = "app.dataseed.enabled", havingValue = "true", matchIfMissing = true)
public class DataSeeder {

    private final RoleRepository roleRepository;
    private final EntityLookupService lookupService;
    private final AppUserRepository appUserRepository;
    private final AuthUserRepository authUserRepository;
    private final EventTypeRepository eventTypeRepository;
    private final EventRepository eventRepository;
    private final PasswordEncoder passwordEncoder;
    private final OccurrenceEventRepository occurrenceEventRepository;
    private final AttendanceRepository attendanceRepository;
    private final AdminEventService adminEventService;

    private final Long YOGA_TYPE_ID = 1L;
    private final Long DANCE_TYPE_ID = 2L;
    private final Long POLEDANCE_TYPE_ID = 3L;


    Role adminRole = new Role("ADMIN");
    Role instructorRole = new Role("INSTRUCTOR");
    Role clientRole = new Role("CLIENT");

    AppUser client;
    List<EventData> events;

    @Transactional
    @PostConstruct
    public void seedData() {
        createRoles();
        createUsers();
        seedEventTypes();
        seedEvents();
        seedAttendancesTransactional();
    }

    private void createRoles() {
        roleRepository.saveAll(Arrays.asList(adminRole, instructorRole, clientRole));
    }

    private void createUsers() {
        createDefaultAdminAndClient();
        createInstructors();
        createClients();
    }

    private void createDefaultAdminAndClient() {
        createUser("admin@yoga.com", "Admin", "Admin", Set.of(adminRole));
        createUser("client1@client.com", "John", "Wick", Set.of(clientRole));
    }

    private void createInstructors() {
        List<AppUser> instructors = Arrays.asList(
                createUser("instructor1@yoga.com", "Jane", "Doe", Set.of(instructorRole)),
                createUser("instructor2@yoga.com", "John", "Smith", Set.of(instructorRole)),
                createUser("instructor3@yoga.com", "Mary", "White", Set.of(instructorRole)),
                createUser("instructor4@yoga.com", "Lucas", "Brown", Set.of(instructorRole))
        );

        appUserRepository.saveAll(instructors);
    }

    private void createClients() {
        IntStream.range(2, 5)
                .forEach(i -> {
                    createUser("client" + i + "@client.com", "Client" + i, "Test", Set.of(clientRole));
                });
    }

    private AuthUser createAuthUser(String email, Set<Role> role) {
        return authUserRepository.save(AuthUser.builder()
                .email(email)
                .password(passwordEncoder.encode("admin"))
                .status(AuthUserStatus.ACTIVE)
                .enabled(true)
                .roles(role)
                .build());
    }

    private AppUser createAppUser(String firstName, String lastName, AuthUser authUser) {
        return appUserRepository.save(AppUser.builder()
                .firstName(firstName)
                .lastName(lastName)
                .authUser(authUser)
                .build());
    }

    private AppUser createUser(String email, String firstName, String lastName, Set<Role> roles) {
        AuthUser authUser = createAuthUser(email, roles);
        return createAppUser(firstName, lastName, authUser);
    }

    private void seedEventTypes() {
        List<EventType> eventTypes = List.of(
                new EventType(YOGA_TYPE_ID, "Yoga", "Morning yoga"),
                new EventType(DANCE_TYPE_ID, "Dance", "Morning dance"),
                new EventType(POLEDANCE_TYPE_ID, "PoleDance", "Morning Pole Dance")
        );
        eventTypeRepository.saveAll(eventTypes);
    }

    private void seedEvents() {
        AppUser admin = lookupService.findUserByEmail("admin@yoga.com");
        AppUser instructor = lookupService.findUserByEmail("instructor1@yoga.com");

        Map<String, EventType> eventTypes = Map.of(
                "Yoga", getEventType("Yoga"),
                "Dance", getEventType("Dance"),
                "PoleDance", getEventType("Pole Dance")
        );

        events = List.of(
            new EventData("Yoga Workshop", "Intensive yoga session", LocalDateTime.now().plusDays(1), 120, 15, eventTypes.get("Yoga"), null),
            new EventData("Dance Workshop", "Intensive dance session", LocalDateTime.now().plusDays(1).withHour(17).withMinute(0), 90, 20, eventTypes.get("Dance"), null),
            new EventData("Morning Tango", "Relaxing Tango session", LocalDateTime.now().minusDays(8).withHour(19).withMinute(0), 90, 25, eventTypes.get("Dance"), null),
            new EventData("Pole Dance Workshop", "Try this", LocalDateTime.now().minusDays(10).withHour(17).withMinute(0), 100, 30, eventTypes.get("PoleDance"), null),
            new EventData("Evening Yoga", "Relaxing yoga session", LocalDateTime.now().minusDays(5).withHour(16).withMinute(0), 100, 30, eventTypes.get("Yoga"), null),
            new EventData("Morning Yoga", "Daily morning yoga sessions", LocalDateTime.now().plusDays(2).withHour(7).withMinute(0), 60, 20, eventTypes.get("Yoga"), "FREQ=WEEKLY;BYDAY=MO,WE,FR;INTERVAL=1;COUNT=12"),
            new EventData("Evening Pole Dance", "Weekly pole dance classes", LocalDateTime.now().plusDays(3).withHour(19).withMinute(0), 75, 12, eventTypes.get("PoleDance"), "FREQ=WEEKLY;BYDAY=TU,TH;INTERVAL=1;COUNT=10")
        );

        events.forEach(event -> {createEventWithOccurrences(event, admin, instructor);});
    }

    private EventType getEventType(String name) {
        return eventTypeRepository.findByName(name).orElseThrow(() -> new RuntimeException("Event type " + name + " not found"));
    }

    private void createEventWithOccurrences(EventData eventData, AppUser admin, AppUser instructor) {
        Event event = createEvent(eventData, admin, instructor);
        List<OccurrenceEvent> occurrenceEvents = adminEventService.generateOccurrences(event);

        if (!occurrenceEvents.isEmpty()) {
            occurrenceEventRepository.saveAll(occurrenceEvents);
        }
    }

    private Event createEvent(EventData eventData, AppUser admin, AppUser instructor) {
        return eventRepository.save(Event.builder()
                .title(eventData.getTitle())
                .description(eventData.getDescription())
                .start(eventData.getStart())
                .durationMinutes(eventData.getDuration())
                .maxParticipants(eventData.getMaxParticipants())
                .eventType(eventData.getEventType())
                .eventTypeName(eventData.getEventType().getName())
                .createdBy(admin)
                .instructor(instructor)
                .status(EventStatus.SCHEDULED)
                .rrule(eventData.getRecurrenceRule())
                .build());
    }

    public void seedAttendancesTransactional() {
        seedAttendances();
    }

    private void seedAttendances() {
        events.forEach(this::seedAttendanceForEvent);
    }

    private void seedAttendanceForEvent(EventData eventData) {
        eventRepository.findByTitle(eventData.getTitle()).flatMap(event -> occurrenceEventRepository.findOccurrencesByEventId(event.getId())
                .stream().findFirst()).ifPresent(occurrence -> {
                    if (!occurrence.getParticipants().contains(client)) {
                        createAttendance(client, occurrence);
                        occurrence.getParticipants().add(client);
                        occurrenceEventRepository.save(occurrence);
                    }
        });
    }

    private void createAttendance(AppUser client, OccurrenceEvent occurrence) {
        attendanceRepository.save(Attendance.builder()
                .user(client)
                .occurrenceEvent(occurrence)
                .status(AttendanceStatus.REGISTERED)
                .build());
    }
}