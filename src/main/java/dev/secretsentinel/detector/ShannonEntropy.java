package dev.secretsentinel.detector;

import java.util.HashMap;
import java.util.Map;

public final class ShannonEntropy {

    private static final double LN2 = Math.log(2.0);

    private ShannonEntropy() {
    }

    public static double calculate(String value) {
        if (value == null || value.isEmpty()) {
            return 0.0;
        }

        Map<Character, Integer> counts = new HashMap<>();
        for (int i = 0; i < value.length(); i++) {
            counts.merge(value.charAt(i), 1, Integer::sum);
        }

        // entropia em bits por caractere, sem normalizar para nao esconder tokens curtos e repetitivos
        double entropy = 0.0;
        for (int count : counts.values()) {
            double probability = (double) count / value.length();
            entropy -= probability * (Math.log(probability) / LN2);
        }
        return entropy;
    }
}
