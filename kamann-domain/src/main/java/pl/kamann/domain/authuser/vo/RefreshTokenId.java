package pl.kamann.domain.authuser.vo;

public record RefreshTokenId(Long value) {
    public static RefreshTokenId generate() {
        return new RefreshTokenId(null);
    }
}