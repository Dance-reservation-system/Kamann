package shared;


public record LoginRequest(
    String email,

    String password
) {}