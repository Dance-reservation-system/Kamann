package pl.kamann.services.admin.update;

public class UpdateStrategyFactory {

    public UpdateStrategy getUpdateStrategy(UpdateCriteria updateCriteria) {
        if (updateCriteria.startAfter() != null & updateCriteria.endBefore() != null) {
            return new UpdateRangeEventsStrategy()
        }
    }
}
