package pl.kamann.domain.appuser.vo;

import pl.kamann.domain.common.Identifier;

import java.util.UUID;

public final class AppUserId extends Identifier {
    public AppUserId(UUID value) {
        super(value);
    }
}