package dev.secretsentinel.detector;

import dev.secretsentinel.model.Finding;
import dev.secretsentinel.model.Severity;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DetectionEngineTest {

    private static final String HIGH_ENTROPY_TOKEN = "aB3xY7qL2pR9sT4vW8zK5mN1";

    private final DetectionEngine engine = new DetectionEngine(4.5);

    @Test
    void detectaChaveAws() {
        Finding finding = first(scan("aws=AKIA" + "A1B2C3D4E5F6G7H8"), "AWS_ACCESS_KEY");
        assertEquals(Severity.CRITICAL, finding.severity());
        assertTrue(finding.maskedValue().startsWith("AKIA****"));
    }

    @Test
    void detectaChavePrivada() {
        Finding finding = scan("-----BEGIN RSA PRIVATE KEY-----").getFirst();
        assertEquals("PRIVATE_KEY", finding.rule());
        assertEquals(Severity.CRITICAL, finding.severity());
    }

    @Test
    void detectaTokenGithub() {
        Finding finding = first(scan("ghp_" + "a".repeat(36)), "GITHUB_TOKEN");
        assertEquals(Severity.CRITICAL, finding.severity());
        assertTrue(finding.maskedValue().startsWith("ghp_"));
    }

    @Test
    void detectaGithubPat() {
        assertFalse(scan("github_pat_" + "a".repeat(40)).isEmpty());
    }

    @Test
    void detectaJwt() {
        String jwt = "eyJ" + "a".repeat(10) + "." + "b".repeat(10) + "." + "c".repeat(10);
        Finding finding = first(scan(jwt), "JWT");
        assertEquals(Severity.HIGH, finding.severity());
    }

    @Test
    void detectaChaveGoogle() {
        Finding finding = first(scan("AIza" + "b".repeat(35)), "GOOGLE_API_KEY");
        assertEquals(Severity.HIGH, finding.severity());
        assertTrue(finding.maskedValue().startsWith("AIza****"));
    }

    @Test
    void detectaAtribuicaoHardcoded() {
        Finding finding = first(scan("String password = \"Sup3rS3cret\";"), "HARDCODED_SECRET");
        assertEquals(Severity.HIGH, finding.severity());
        assertTrue(finding.maskedValue().startsWith("S****"));
    }

    @Test
    void detectaAtribuicaoComPrefixo() {
        Finding finding = first(scan("DATABASE_PASSWORD=Sup3rS3cret"), "HARDCODED_SECRET");
        assertEquals(Severity.HIGH, finding.severity());
    }

    @Test
    void detectaTokenPorEntropia() {
        List<Finding> findings = engine.analyze("test.txt", 7, "custom=" + HIGH_ENTROPY_TOKEN);
        Finding finding = first(findings, "HIGH_ENTROPY");
        assertEquals(7, finding.line());
        assertEquals(Severity.MEDIUM, finding.severity());
        assertTrue(finding.entropy() > 4.5);
    }

    @Test
    void naoSoFreBacktrackingComLinhaHostil() {
        String hostile = "a.".repeat(20_000);
        assertTimeoutPreemptively(Duration.ofSeconds(2),
                () -> assertTrue(scan(hostile).isEmpty()));
    }

    @Test
    void naoMarcaChamadaDeMetodoComoSegredo() {
        assertTrue(scan("String token = candidates.group();").isEmpty());
    }

    @Test
    void entropiaNaoRepeteSegredoJaDetectadoPorRegex() {
        List<Finding> findings = scan("GITHUB_TOKEN=ghp_" + "a".repeat(36));
        assertTrue(findings.stream().noneMatch(finding -> finding.rule().equals("HIGH_ENTROPY")));
    }

    @Test
    void limiteDeEntropiaConfiguravel() {
        DetectionEngine strict = new DetectionEngine(6.0);
        assertTrue(strict.analyze("test.txt", 1, "custom=" + HIGH_ENTROPY_TOKEN).isEmpty());
    }

    @Test
    void naoMarcaUrlImportOuCaminho() {
        assertTrue(scan("https://example.com/docs/getting-started").isEmpty());
        assertTrue(scan("import java.util.concurrent.Executors;").isEmpty());
        assertTrue(scan("caminho: C:/Users/demo/Projetos/secret-sentinel").isEmpty());
    }

    @Test
    void naoRepeteOMesmoValorDuasVezes() {
        String key = "AKIA" + "A1B2C3D4E5F6G7H8";
        List<Finding> findings = scan("api_key=" + key);
        assertEquals(1, findings.stream().filter(f -> f.maskedValue().startsWith("AKIA****")).count());
    }

    private List<Finding> scan(String line) {
        return engine.analyze("test.txt", 1, line);
    }

    private static Finding first(List<Finding> findings, String rule) {
        Finding finding = findings.stream()
                .filter(candidate -> candidate.rule().equals(rule))
                .findFirst()
                .orElse(null);
        assertNotNull(finding, "regra nao encontrada: " + rule);
        return finding;
    }
}
