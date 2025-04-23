package pl.kamann.testsupport;

import pl.kamann.domain.appuser.AppUser;

import java.lang.reflect.Field;

public class AppUserTestFactory {

    public static AppUser withId(Long id) {
        try {
            AppUser user = createEmpty();
            Field idField = AppUser.class.getDeclaredField("id");
            idField.setAccessible(true);
            idField.set(user, id);
            return user;
        } catch (Exception e) {
            throw new RuntimeException("Failed to build AppUser for test", e);
        }
    }

    private static AppUser createEmpty() throws Exception {
        var constructor = AppUser.class.getDeclaredConstructor();
        constructor.setAccessible(true);
        return constructor.newInstance();
    }
}