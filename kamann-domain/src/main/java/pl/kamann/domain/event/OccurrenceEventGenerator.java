package pl.kamann.domain.event;

import lombok.RequiredArgsConstructor;
import org.dmfs.rfc5545.DateTime;
import org.dmfs.rfc5545.recur.RecurrenceRule;
import org.dmfs.rfc5545.recur.RecurrenceRuleIterator;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.kamann.domain.event.exceptions.EventCodes;
import pl.kamann.domain.event.model.Event;
import pl.kamann.domain.event.model.OccurrenceEvent;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class OccurrenceEventGenerator {

    public List<OccurrenceEvent> generateOccurrences(Event event) {
        List<OccurrenceEvent> occurrences = new ArrayList<>();
        if (event.getRrule() == null || event.getRrule().isEmpty()) {
            occurrences.add(OccurrenceEvent.create(event, event.getStart(), event.getCreatedBy()));
            return occurrences;
        }

        try {
            RecurrenceRule rule = new RecurrenceRule(event.getRrule());
            DateTime dtStart = new DateTime(event.getStart().atZone(ZoneId.systemDefault()).toInstant().toEpochMilli());
            RecurrenceRuleIterator iterator = rule.iterator(dtStart);

            int maxInstances = 25;
            int seriesIndex = 1;
            while (iterator.hasNext() && maxInstances-- > 0) {
                DateTime nextDateTime = iterator.nextDateTime();
                LocalDateTime occurrenceStart = LocalDateTime.ofInstant(
                        Instant.ofEpochMilli(nextDateTime.getTimestamp()),
                        ZoneId.systemDefault()
                );

                OccurrenceEvent occurrence = OccurrenceEvent.create(event, occurrenceStart, event.getCreatedBy());
                occurrence.setSeriesIndex(seriesIndex++);
                occurrences.add(occurrence);
            }
        } catch (Exception e) {
//            throw new ApiException("Failed to generate occurrences: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR, EventCodes.OCCURRENCE_GENERATION_FAILED.name());
        }

        return occurrences;
    }
}