package dev.secretsentinel.detector;

import dev.secretsentinel.model.Finding;
import dev.secretsentinel.model.Severity;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class DetectionEngine {

    private static final Pattern TOKEN_CANDIDATE = Pattern.compile("[A-Za-z0-9+/=_-]{20,}");
    private static final Pattern CODE_EXPRESSION = Pattern.compile("^[A-Za-z_$][\\w$.]*\\([^)]*\\)$");

    private static final List<Rule> RULES = List.of(
            new Rule("AWS_ACCESS_KEY", Pattern.compile("\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b"), Severity.CRITICAL, 0),
            new Rule("PRIVATE_KEY", Pattern.compile("-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"), Severity.CRITICAL, 0),
            new Rule("GITHUB_TOKEN", Pattern.compile("\\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{30,})\\b"), Severity.CRITICAL, 0),
            new Rule("JWT", Pattern.compile("\\beyJ[A-Za-z0-9_-]{8,}+\\.[A-Za-z0-9_-]{8,}+\\.[A-Za-z0-9_-]{8,}+\\b"), Severity.HIGH, 0),
            new Rule("GOOGLE_API_KEY", Pattern.compile("\\bAIza[0-9A-Za-z_-]{35}\\b"), Severity.HIGH, 0),
            new Rule("HARDCODED_SECRET", Pattern.compile("(?i)(?<![A-Za-z0-9])(password|passwd|pwd|secret|api[_-]?key|token)\\b\\s*[:=]\\s*[\"']?([^\"'\\s,;]{6,})[\"']?"), Severity.HIGH, 2)
    );

    private final double entropyThreshold;

    public DetectionEngine(double entropyThreshold) {
        this.entropyThreshold = entropyThreshold;
    }

    public List<Finding> analyze(String path, int lineNumber, String line) {
        List<RawMatch> matches = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();

        for (Rule rule : RULES) {
            Matcher matcher = rule.pattern().matcher(line);
            while (matcher.find()) {
                String value = rule.valueGroup() == 0 ? matcher.group() : matcher.group(rule.valueGroup());
                if (value == null || value.isBlank() || !seen.add(value)) {
                    continue;
                }
                // atribuicoes de codigo como token = metodo() nao sao segredos
                if (rule.name().equals("HARDCODED_SECRET") && CODE_EXPRESSION.matcher(value).matches()) {
                    continue;
                }
                matches.add(new RawMatch(value, rule.name(), rule.severity(), ShannonEntropy.calculate(value)));
            }
        }

        Matcher candidates = TOKEN_CANDIDATE.matcher(line);
        while (candidates.find()) {
            String token = candidates.group();
            if (!seen.add(token) || !isPlausibleToken(token) || overlapsKnownSecret(matches, token)) {
                continue;
            }
            double entropy = ShannonEntropy.calculate(token);
            if (entropy >= entropyThreshold) {
                matches.add(new RawMatch(token, "HIGH_ENTROPY", Severity.MEDIUM, entropy));
            }
        }

        List<Finding> findings = new ArrayList<>(matches.size());
        for (RawMatch match : matches) {
            findings.add(new Finding(path, lineNumber, match.rule(), match.severity(),
                    Masking.mask(match.value()), match.entropy()));
        }
        return findings;
    }

    // o token candidato pode incluir o nome da variavel e o "=", ou ser parte de um jwt
    private static boolean overlapsKnownSecret(List<RawMatch> matches, String token) {
        for (RawMatch match : matches) {
            if (match.value().contains(token) || token.contains(match.value())) {
                return true;
            }
        }
        return false;
    }

    private static boolean isPlausibleToken(String token) {
        String lower = token.toLowerCase(Locale.ROOT);
        if (lower.startsWith("http") || lower.contains("://") || lower.startsWith("www.")
                || lower.startsWith("com.") || lower.startsWith("import") || lower.startsWith("package")) {
            return false;
        }
        if (lower.contains(".com") || lower.contains(".org") || lower.contains(".net")
                || lower.contains(".java") || lower.contains(".class") || lower.contains(".yml")
                || lower.contains(".yaml") || lower.contains(".json") || lower.contains(".lock")) {
            return false;
        }
        if (token.startsWith("/") || token.startsWith("./") || token.startsWith("../")
                || token.startsWith("C:") || token.contains("\\")) {
            return false;
        }
        // caminhos com mais de uma barra e identificadores so com letras geram muito ruido
        if (token.chars().filter(character -> character == '/').count() > 1) {
            return false;
        }

        boolean hasDigit = false;
        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasSymbol = false;
        for (int i = 0; i < token.length(); i++) {
            char character = token.charAt(i);
            hasDigit |= Character.isDigit(character);
            hasUpper |= Character.isUpperCase(character);
            hasLower |= Character.isLowerCase(character);
            hasSymbol |= !Character.isLetterOrDigit(character);
        }
        int classes = (hasDigit ? 1 : 0) + (hasUpper ? 1 : 0) + (hasLower ? 1 : 0) + (hasSymbol ? 1 : 0);
        return classes >= 2 && (hasDigit || hasSymbol);
    }

    private record RawMatch(String value, String rule, Severity severity, double entropy) {
    }
}
