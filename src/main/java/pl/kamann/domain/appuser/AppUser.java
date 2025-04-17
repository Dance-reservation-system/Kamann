package pl.kamann.domain.appuser;

import jakarta.persistence.*;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Objects;

@Entity
public class AppUser implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private Long authUserId;

    @Column(nullable = false)
    private String firstName;

    @Column(nullable = false)
    private String lastName;

    private String phone;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;

    private AppUser() {
    }

    private AppUser(String firstName, String lastName, String phone, Long authUserId) {
        this.firstName = Objects.requireNonNull(firstName, "First name cannot be null");
        this.lastName = Objects.requireNonNull(lastName, "Last name cannot be null");
        this.phone = phone;
        this.authUserId = authUserId;
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    public static AppUser create(String firstName, String lastName, String phone, Long authUserId) {
        return new AppUser(firstName, lastName, phone, authUserId);
    }

    public void changePhone(String newPhone) {
        if (newPhone != null && !newPhone.trim().isEmpty()) {
            this.phone = newPhone;
            this.updatedAt = LocalDateTime.now();
        } else {
            throw new IllegalArgumentException("Phone number cannot be empty.");
        }
    }

    public void changeFirstName(String newFirstName) {
        if (newFirstName != null && !newFirstName.trim().isEmpty()) {
            this.firstName = newFirstName;
            this.updatedAt = LocalDateTime.now();
        } else {
            throw new IllegalArgumentException("First name cannot be empty.");
        }
    }

    public void changeLastName(String newLastName) {
        if (newLastName != null && !newLastName.trim().isEmpty()) {
            this.lastName = newLastName;
            this.updatedAt = LocalDateTime.now();
        } else {
            throw new IllegalArgumentException("Last name cannot be empty.");
        }
    }

    public Long getId() {
        return id;
    }

    public Long getAuthUserId() {
        return authUserId;
    }

    public void setAuthUserId(Long authUserId) {
        this.authUserId = authUserId;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public String getPhone() {
        return phone;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AppUser appUser = (AppUser) o;
        return Objects.equals(id, appUser.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}