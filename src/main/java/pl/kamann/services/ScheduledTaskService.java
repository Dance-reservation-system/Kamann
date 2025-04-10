package pl.kamann.services;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import pl.kamann.entities.appuser.AuthUser;
import pl.kamann.entities.appuser.AuthUserStatus;
import pl.kamann.repositories.AuthUserRepository;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.*;

@Service
@Slf4j
@RequiredArgsConstructor
public class ScheduledTaskService {

    private final ScheduledExecutorService scheduledExecutorService = Executors.newScheduledThreadPool(1);
    private final Map<String, ScheduledFuture<?>> deletionTasks = new ConcurrentHashMap<>();
    private final AuthUserRepository authUserRepository;

    public void scheduleDeletionUser(String email) {
        cancelTask(email);

        ScheduledFuture<?> task = scheduledExecutorService.schedule(() -> {
            Optional<AuthUser> authUserOptional = authUserRepository.findByEmail(email);
            if (authUserOptional.isPresent() && !authUserOptional.get().isEnabled()) {
                authUserRepository.delete(authUserOptional.get());
                log.info("User {} deleted due to inactivity after {} minutes", email, 15);
            }
            deletionTasks.remove(email);
        }, 15, TimeUnit.MINUTES);

        deletionTasks.put(email, task);
    }

    public void scheduledSoftDeletionUser(AuthUser authUser) {
        cancelTask(authUser.getEmail());

        ScheduledFuture<?> task = scheduledExecutorService.schedule(() -> {
            if (authUser.getStatus() == AuthUserStatus.PENDING_DELETION) {
                authUser.setEnabled(false);
                authUser.setStatus(AuthUserStatus.DELETED);
                authUser.setEmail("deleted-" + authUser.getEmail());
                authUserRepository.save(authUser);
            }
            deletionTasks.remove(authUser.getEmail());
            log.info("User {} deleted due to inactivity after {} days", authUser.getEmail(), 3);
        }, 3, TimeUnit.DAYS);

        deletionTasks.put(authUser.getEmail(), task);
    }

    public void cancelTask(String email) {
        ScheduledFuture<?> task = deletionTasks.get(email);
        if (task != null && !task.isDone() && !task.isCancelled()) {
            task.cancel(false);
            log.info("Cancelled scheduled task for user: {}", email);
        }
        deletionTasks.remove(email);
    }
}
