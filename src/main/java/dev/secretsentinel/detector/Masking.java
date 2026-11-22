package dev.secretsentinel.detector;

public final class Masking {

    private Masking() {
    }

    public static String mask(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        if (value.length() < 2) {
            return "*";
        }

        // mostra poucos caracteres em segredos curtos para nao devolver quase o valor original
        int visible = value.length() >= 20 ? 4 : value.length() >= 13 ? 2 : 1;
        int stars = Math.max(4, Math.min(12, value.length() - 2 * visible));
        return value.substring(0, visible) + "*".repeat(stars)
                + value.substring(value.length() - visible);
    }
}
