package pl.kamann.utility;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import pl.kamann.entities.appuser.AppUser;
import pl.kamann.entities.appuser.AppUserStatus;
import pl.kamann.entities.appuser.Role;
import pl.kamann.entities.event.Event;
import pl.kamann.entities.event.EventStatus;
import pl.kamann.entities.event.EventType;
import pl.kamann.mappers.EventMapper;
import pl.kamann.repositories.*;
import pl.kamann.services.EventValidationService;
import pl.kamann.services.OccurrenceService;
import pl.kamann.services.admin.AdminEventService;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Component
public class DataSeeder {

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private EventMapper eventMapper;

    @Autowired
    private AppUserRepository appUserRepository;

    @Autowired
    private EventTypeRepository eventTypeRepository;

    @Autowired
    private EventRepository eventRepository;

    @Autowired
    private MembershipCardRepository membershipCardRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private OccurrenceEventRepository occurrenceEventRepository;

    @Autowired
    private OccurrenceService occurrenceService;

    @Autowired
    private EventValidationService eventValidationService;

    @Autowired
    private AttendanceRepository attendanceRepository;

    @Autowired
    private AdminEventService adminEventService;

    Role adminRole = new Role("ADMIN");
    Role instructorRole = new Role("INSTRUCTOR");
    Role clientRole = new Role("CLIENT");

    @PostConstruct
    public void seedData() {
        createRoles();
        createUsers();
        seedEventTypes();
        seedEvents();
    }
    private void createRoles() {
        roleRepository.saveAll(Arrays.asList(adminRole, instructorRole, clientRole));
    }

    private void createUsers() {
        createAdmin();
        createInstructors();
        createClients();
    }

    private void createAdmin() {
        AppUser admin = AppUser.builder()
                .email("admin@yoga.com")
                .firstName("Admin")
                .lastName("Admin")
                .password(passwordEncoder.encode("admin"))
                .roles(Set.of(adminRole))
                .build();

        appUserRepository.save(admin);
    }

    private void createInstructors() {
        List<AppUser> instructors = Arrays.asList(
                createInstructor("instructor1@yoga.com", "Jane", "Doe", instructorRole),
                createInstructor("instructor2@yoga.com", "John", "Smith", instructorRole),
                createInstructor("instructor3@yoga.com", "Mary", "White", instructorRole),
                createInstructor("instructor4@yoga.com", "Lucas", "Brown", instructorRole)
        );

        appUserRepository.saveAll(instructors);
    }

    private void createClients() {
        List<AppUser> clients = IntStream.range(1, 5)
                .mapToObj(i -> AppUser.builder()
                        .email("client" + i + "@client.com")
                        .firstName("Client" + i)
                        .lastName("Test")
                        .password(passwordEncoder.encode("admin"))
                        .roles(new HashSet<>(Collections.singletonList(clientRole)))
                        .status(AppUserStatus.ACTIVE)
                        .build())
                .collect(Collectors.toList());

        appUserRepository.saveAll(clients);
    }

    private AppUser createInstructor(String email, String firstName, String lastName, Role role) {
        return AppUser.builder()
                .email(email)
                .firstName(firstName)
                .lastName(lastName)
                .password(passwordEncoder.encode("admin"))
                .roles(new HashSet<>(Collections.singletonList(role)))
                .status(AppUserStatus.ACTIVE)
                .build();
    }

    private void seedEventTypes() {
        List<EventType> eventTypes = new ArrayList<>();
        eventTypes.add(new EventType(1L, "Yoga", "Morning yoga"));
        eventTypes.add(new EventType(2L, "Dance", "Morning dance"));
        eventTypes.add(new EventType(3L, "PoleDance", "Morning Pole Dance"));

        eventTypes.forEach(eventType -> eventTypeRepository.save(eventType));
    }

    private void seedEvents() {
        AppUser admin = appUserRepository.findByEmail("admin@yoga.com")
                .orElseThrow(() -> new RuntimeException("Admin not found"));
        AppUser instructor = appUserRepository.findByEmail("instructor1@yoga.com")
                .orElseThrow(() -> new RuntimeException("Instructor not found"));
        EventType yogaType = eventTypeRepository.findByName("Yoga")
                .orElseThrow(() -> new RuntimeException("Event type not found"));

        // Create single events
        createSingleYogaWorkshop(admin, instructor, yogaType);

        // Create recurring events
        createRecurringMorningYoga(admin, instructor, yogaType);
    }

    private void createSingleYogaWorkshop(AppUser admin, AppUser instructor, EventType yogaType) {
        Event event = Event.builder()
                .title("Yoga Workshop")
                .description("Intensive yoga session")
                .start(LocalDateTime.of(2025, 2, 8, 18, 0))
                .durationMinutes(120)
                .maxParticipants(15)
                .eventType(yogaType)
                .createdBy(admin)
                .instructor(instructor)
                .status(EventStatus.SCHEDULED)
                .build();

        eventRepository.save(event);
        adminEventService.createSingleOccurrence(event);
    }

    private void createRecurringMorningYoga(AppUser admin, AppUser instructor, EventType yogaType) {
        Event event = Event.builder()
                .title("Morning Yoga")
                .description("Daily morning yoga sessions")
                .rrule("FREQ=WEEKLY;BYDAY=MO,WE,FR;INTERVAL=1;COUNT=12")
                .start(LocalDateTime.of(2025, 2, 6, 7, 0))
                .durationMinutes(60)
                .maxParticipants(20)
                .eventType(yogaType)
                .createdBy(admin)
                .instructor(instructor)
                .status(EventStatus.SCHEDULED)
                .build();

        eventRepository.save(event);
        adminEventService.createRecurringOccurrences(event);
    }
}