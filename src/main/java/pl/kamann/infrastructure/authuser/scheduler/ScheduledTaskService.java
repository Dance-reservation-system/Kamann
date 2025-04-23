/**
 * Ubiquitous Language Summary:
 * Infrastructure scheduler that handles time-based user lifecycle transitions,
 * such as removing unconfirmed or inactive accounts after a delay.
 */
package pl.kamann.infrastructure.authuser.scheduler;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.appuser.repository.AppUserRepository;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.AuthUserRepository;
import pl.kamann.domain.authuser.Email;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
@RequiredArgsConstructor
public class ScheduledTaskService {

    private static final int UNCONFIRMED_REMOVAL_DELAY_MINUTES = 15;
    private static final int DELETION_FINALIZATION_DELAY_DAYS = 3;

    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private final Map<String, ScheduledFuture<?>> tasks = new ConcurrentHashMap<>();
    private final AuthUserRepository authUserRepository;
    private final AppUserRepository appUserRepository;

    public void scheduleUnconfirmedAccountRemoval(Email email) {
        String emailKey = email.getValue();
        cancelPendingDeletionTask(emailKey);

        ScheduledFuture<?> task = scheduler.schedule(() -> {
            authUserRepository.findByEmail(email).ifPresent(authUser -> {
                if (!authUser.isEnabled()) {
                    authUserRepository.delete(authUser);
                    log.info("User {} deleted due to unconfirmed registration after {} minutes", email, UNCONFIRMED_REMOVAL_DELAY_MINUTES);
                }
            });
            tasks.remove(emailKey);
        }, UNCONFIRMED_REMOVAL_DELAY_MINUTES, TimeUnit.MINUTES);

        tasks.put(emailKey, task);
    }

    public void schedulePendingDeletionFinalization(AuthUser authUser) {
        String emailKey = authUser.getEmail().getValue();
        cancelPendingDeletionTask(emailKey);

        ScheduledFuture<?> task = scheduler.schedule(() -> {
            AppUser appUser = appUserRepository.findByAuthUser(authUser).orElse(null);
            if (appUser != null) {
                appUser.finalizeAccountIfInactive();
                authUserRepository.save(authUser);
                log.info("User {} finalized deletion after {} days", emailKey, DELETION_FINALIZATION_DELAY_DAYS);
            }
            tasks.remove(emailKey);
        }, DELETION_FINALIZATION_DELAY_DAYS, TimeUnit.DAYS);

        tasks.put(emailKey, task);
    }

    public void cancelPendingDeletionTask(String emailKey) {
        ScheduledFuture<?> task = tasks.remove(emailKey);
        if (task != null && !task.isDone() && !task.isCancelled()) {
            task.cancel(false);
            log.info("Cancelled scheduled task for user: {}", emailKey);
        }
    }
}