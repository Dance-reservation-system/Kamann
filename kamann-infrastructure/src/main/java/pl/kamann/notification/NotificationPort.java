package pl.kamann.notification;

import pl.kamann.domain.authuser.aggregate.AuthUser;

public interface NotificationPort {
    void notifyAdminsOfInstructorRequest(AuthUser adminUser, String confirmationLink);
    void notifyInstructorOfSubmission(AuthUser instructor);
    void notifyClientOfRegistration(AuthUser client, String confirmationLink);
    void notifyUserOfAccountConfirmation(AuthUser user);
}
