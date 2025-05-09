package shared;

public record LoginResponse(String accessToken, String email, String fullName) {}