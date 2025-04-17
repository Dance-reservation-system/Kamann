package pl.kamann.domain.facility;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalTime;
import java.util.Objects;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
class Facility {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String address;

    @Column(nullable = false)
    private LocalTime openingHours;

    @Column(nullable = false)
    private LocalTime closingHours;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Facility facility = (Facility) o;
        return id == facility.id && Objects.equals(name, facility.name) && Objects.equals(address, facility.address);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, name, address);
    }
}
