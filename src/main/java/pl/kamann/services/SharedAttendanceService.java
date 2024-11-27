package pl.kamann.services;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.kamann.entities.Attendance;
import pl.kamann.repositories.AttendanceRepository;
import pl.kamann.config.exception.handler.ApiException;
import pl.kamann.config.global.Codes;
import pl.kamann.entities.Event;
import pl.kamann.entities.MembershipCard;
import pl.kamann.repositories.MembershipCardRepository;
import pl.kamann.entities.AppUser;
import pl.kamann.utility.EntityLookupService;

@Service
@RequiredArgsConstructor
public class SharedAttendanceService {

    private final AttendanceRepository attendanceRepository;
    private final MembershipCardRepository membershipCardRepository;
    private final EntityLookupService lookupService;

    public Attendance getAttendance(Long eventId, Long userId) {
        AppUser user = lookupService.findUserById(userId);
        Event event = lookupService.findEventById(eventId);
        return attendanceRepository.findByUserAndEvent(user, event)
                .orElseThrow(() -> new ApiException("Attendance not found.", HttpStatus.NOT_FOUND, Codes.ATTENDANCE_NOT_FOUND));
    }

    @Transactional
    public void deductMembershipEntry(Long userId) {
//        MembershipCard card = membershipCardRepository.findByUserId(userId)
//                .orElseThrow(() -> new ApiException("Membership card not found.", HttpStatus.NOT_FOUND, Codes.CARD_NOT_FOUND));

//        if (card.getEntrancesLeft() <= 0) {
//            throw new ApiException("No available entries left on membership card.", HttpStatus.BAD_REQUEST, Codes.NO_ENTRANCES_LEFT);
//        }
//
//        card.setEntrancesLeft(card.getEntrancesLeft() - 1);
//        membershipCardRepository.save(card);
    }
}
