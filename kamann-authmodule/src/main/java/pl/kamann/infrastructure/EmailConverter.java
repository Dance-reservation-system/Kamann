package pl.kamann.infrastructure;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import pl.kamann.domain.Email;

@Converter(autoApply = true)
public class EmailConverter implements AttributeConverter<Email, String> {

    @Override
    public String convertToDatabaseColumn(Email email) {
        return email != null ? email.value() : null;
    }

    @Override
    public Email convertToEntityAttribute(String dbValue) {
        return dbValue != null ? new Email(dbValue) : null;
    }
}