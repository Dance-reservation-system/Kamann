package pl.kamann.domain.vo;

public record RefreshTokenId(Long value) {
    public static RefreshTokenId generate() {
        return new RefreshTokenId(null);
    }
}