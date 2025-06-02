package pl.kamann.domain.port;


import pl.kamann.domain.entity.AuthUser;

public interface NotificationPort {
    void notifyAdminsOfInstructorRequest(AuthUser adminUser, String confirmationLink);
    void notifyInstructorOfSubmission(AuthUser instructor);
    void notifyClientOfRegistration(AuthUser client, String confirmationLink);
    void notifyUserOfAccountConfirmation(AuthUser user);
}
