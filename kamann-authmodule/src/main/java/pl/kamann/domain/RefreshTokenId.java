package pl.kamann.domain;

public record RefreshTokenId(Long value) {
    public static RefreshTokenId generate() {
        return new RefreshTokenId(null);
    }
}