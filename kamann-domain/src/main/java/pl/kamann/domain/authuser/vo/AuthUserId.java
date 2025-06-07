package pl.kamann.domain.authuser.vo;

import pl.kamann.domain.common.Identifier;

import java.util.UUID;

public final class AuthUserId extends Identifier {
  public AuthUserId(Long value) {
    super(value);
  }
}