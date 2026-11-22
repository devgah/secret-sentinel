package dev.secretsentinel.report;

import dev.secretsentinel.cli.CliArguments;
import dev.secretsentinel.model.Finding;
import dev.secretsentinel.model.ScanResult;
import dev.secretsentinel.model.Severity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReportWriterTest {

    @TempDir
    Path temp;

    @Test
    void htmlEscapaTagESanitizaControle() throws IOException {
        Finding finding = new Finding("a/<b>&c.txt", 3, "REGA\u001B[31m",
                Severity.HIGH, "ghp_************1234", 5.0);
        Path output = temp.resolve("report.html");

        ReportWriter.write(new ScanResult(List.of(finding), 1, 12),
                CliArguments.ReportFormat.HTML, output);

        String html = Files.readString(output);
        assertFalse(html.contains("\u001B"));
        assertTrue(html.contains("a/&lt;b&gt;&amp;c.txt"));
        assertTrue(html.contains("REGA?[31m"));
    }

    @Test
    void markdownEscapaPipeEDeslocamento() throws IOException {
        Finding finding = new Finding("a|b.txt", 1, "HIGH_ENTROPY",
                Severity.MEDIUM, "ab\u202Acd", 4.6);
        Path output = temp.resolve("report.md");

        ReportWriter.write(new ScanResult(List.of(finding), 1, 7),
                CliArguments.ReportFormat.MD, output);

        String markdown = Files.readString(output);
        assertTrue(markdown.contains("a\\|b.txt"));
        assertFalse(markdown.contains("\u202A"));
    }

    @Test
    void markdownEscapaBacktickEAngulos() throws IOException {
        Finding finding = new Finding("a<b>.txt", 2, "R`ULE",
                Severity.MEDIUM, "x`y<z>", 4.6);
        Path output = temp.resolve("report2.md");

        ReportWriter.write(new ScanResult(List.of(finding), 1, 7),
                CliArguments.ReportFormat.MD, output);

        String markdown = Files.readString(output);
        assertTrue(markdown.contains("a&lt;b&gt;.txt"));
        assertTrue(markdown.contains("R\\`ULE"));
        assertTrue(markdown.contains("x\\`y&lt;z&gt;"));
    }
}
