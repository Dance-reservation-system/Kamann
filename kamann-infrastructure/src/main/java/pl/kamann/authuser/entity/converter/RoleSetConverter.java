package pl.kamann.authuser.entity.converter;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import pl.kamann.domain.authuser.vo.Role;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

@Converter
public class RoleSetConverter implements AttributeConverter<Set<Role>, String> {

    @Override
    public String convertToDatabaseColumn(Set<Role> roles) {
        if (roles == null || roles.isEmpty()) return "";
        return roles.stream()
                .map(Role::name)
                .collect(Collectors.joining(","));
    }

    @Override
    public Set<Role> convertToEntityAttribute(String dbData) {
        if (dbData == null || dbData.isBlank()) return Collections.emptySet();
        return Arrays.stream(dbData.split(","))
                .map(String::trim)
                .map(Role::fromName)
                .collect(Collectors.toSet());
    }
}