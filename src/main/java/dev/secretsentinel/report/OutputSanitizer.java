package dev.secretsentinel.report;

public final class OutputSanitizer {

    private OutputSanitizer() {
    }

    public static String clean(String value) {
        if (value == null) {
            return "";
        }

        StringBuilder clean = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char character = value.charAt(i);
            // remove controles ANSI, bidi e quebras que podem falsificar a saida
            boolean invisibleControl = character >= '\u200B' && character <= '\u200F'
                    || character >= '\u2028' && character <= '\u202E'
                    || character >= '\u2066' && character <= '\u2069';
            clean.append(Character.isISOControl(character) || invisibleControl ? '?' : character);
        }
        return clean.toString();
    }
}
