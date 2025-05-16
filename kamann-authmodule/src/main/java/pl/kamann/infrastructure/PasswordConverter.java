package pl.kamann.infrastructure;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import pl.kamann.domain.Password;

@Converter(autoApply = true)
public class PasswordConverter implements AttributeConverter<Password, String> {

    @Override
    public String convertToDatabaseColumn(Password password) {
        return password != null ? password.value() : null;
    }

    @Override
    public Password convertToEntityAttribute(String dbValue) {
        return dbValue != null ? new Password(dbValue) : null;
    }
}