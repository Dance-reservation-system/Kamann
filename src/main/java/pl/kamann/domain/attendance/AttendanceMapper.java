package pl.kamann.domain.attendance;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import pl.kamann.domain.attendance.dto.AttendanceDetailsDto;

@Mapper(componentModel = "spring")
public interface AttendanceMapper {
    @Mapping(target = "occurrenceEventId", source = "occurrenceEvent.id")
    @Mapping(target = "userId", source = "user.id")
    AttendanceDetailsDto toAttendanceDetailsDto(Attendance attendance);

  }
