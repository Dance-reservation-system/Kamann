package pl.kamann.application;


import pl.kamann.domain.AuthUser;

public interface NotificationPort {
    void notifyAdminsOfInstructorRequest(AuthUser adminUser, String confirmationLink);
    void notifyInstructorOfSubmission(AuthUser instructor);
    void notifyClientOfRegistration(AuthUser client, String confirmationLink);
    void notifyUserOfAccountConfirmation(AuthUser user);
}
