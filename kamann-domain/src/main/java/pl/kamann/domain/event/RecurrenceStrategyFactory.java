package pl.kamann.domain.event;

import pl.kamann.domain.event.model.Event;

public class RecurrenceStrategyFactory {
    public static RecurrenceStrategy getStrategy(Event event) {
        if (event.getRrule() == null || event.getRrule().isEmpty()) {
            return null;
        }
        String rule = event.getRrule().toUpperCase();
        if (rule.contains("DAILY")) {
            return new DailyRecurrenceStrategy();
        }
        if (rule.contains("WEEKLY")) {
            return new WeeklyRecurrenceStrategy();
        }
        if (rule.contains("MONTHLY")) {
            return new MonthlyRecurrenceStrategy();
        }
        return null;
    }
}
