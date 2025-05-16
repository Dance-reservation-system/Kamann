package pl.kamann.domain;


import pl.kamann.application.Identifier;

import java.util.UUID;

public final class AuthUserId extends Identifier {
    public AuthUserId(UUID value) {
        super(value);
    }
}