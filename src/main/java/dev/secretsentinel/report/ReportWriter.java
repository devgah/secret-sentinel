package dev.secretsentinel.report;

import dev.secretsentinel.cli.CliArguments.ReportFormat;
import dev.secretsentinel.model.Finding;
import dev.secretsentinel.model.ScanResult;
import dev.secretsentinel.model.Severity;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Locale;

public final class ReportWriter {

    private ReportWriter() {
    }

    public static void write(ScanResult result, ReportFormat format, Path output) throws IOException {
        String content = switch (format) {
            case HTML -> html(result);
            case MD -> markdown(result);
            case NONE -> "";
        };

        Path parent = output.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        // nao segue symlink no arquivo de saida para nao sobrescrever alvo inesperado
        try (OutputStream stream = Files.newOutputStream(output,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
            stream.write(content.getBytes(StandardCharsets.UTF_8));
        }
    }

    private static String html(ScanResult result) {
        StringBuilder out = new StringBuilder();
        out.append("""
                <!DOCTYPE html>
                <html lang="pt-br">
                <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>SecretSentinel - relatorio</title>
                <style>
                  :root { color-scheme: dark; }
                  * { box-sizing: border-box; }
                  body { margin: 0; padding: 32px; background: #0d1117; color: #c9d1d9;
                         font: 14px/1.5 ui-monospace, SFMono-Regular, Consolas, monospace; }
                  h1 { margin: 0 0 4px; color: #f0f6fc; font-size: 24px; }
                  .sub { color: #8b949e; margin-bottom: 24px; }
                  .cards { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 28px; }
                  .card { flex: 1 1 160px; padding: 16px; border: 1px solid #30363d;
                          border-radius: 8px; background: #161b22; }
                  .card span { display: block; color: #8b949e; font-size: 12px; text-transform: uppercase; }
                  .card strong { display: block; margin-top: 6px; font-size: 26px; color: #f0f6fc; }
                  .card.critical strong { color: #ff5c5c; }
                  .card.high strong { color: #ffc857; }
                  .card.medium strong { color: #4dd0e1; }
                  .card.clean strong { color: #3fb950; }
                  table { width: 100%; border-collapse: collapse; background: #161b22;
                          border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }
                  th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #30363d; }
                  th { color: #8b949e; font-weight: 600; background: #21262d; }
                  tr:last-child td { border-bottom: none; }
                  .sev { font-weight: 700; }
                  .sev.CRITICAL { color: #ff5c5c; }
                  .sev.HIGH { color: #ffc857; }
                  .sev.MEDIUM { color: #4dd0e1; }
                  code { color: #a5d6ff; }
                </style>
                </head>
                <body>
                """);

        out.append("<h1>SecretSentinel</h1>\n");
        out.append("<div class=\"sub\">relatorio de deteccao de segredos</div>\n");
        out.append("<div class=\"cards\">\n");
        out.append(card("arquivos", String.valueOf(result.filesScanned()), ""));
        out.append(card("tempo (ms)", String.valueOf(result.durationMillis()), ""));
        out.append(card("achados", String.valueOf(result.findings().size()), ""));
        out.append(card("criticos", String.valueOf(result.count(Severity.CRITICAL)), "critical"));
        out.append(card("altos", String.valueOf(result.count(Severity.HIGH)), "high"));
        out.append(card("medios", String.valueOf(result.count(Severity.MEDIUM)), "medium"));
        if (result.findings().isEmpty()) {
            out.append(card("status", "limpo", "clean"));
        }
        out.append("</div>\n");

        out.append("<table>\n<thead><tr><th>arquivo</th><th>linha</th><th>regra</th>")
                .append("<th>severidade</th><th>valor mascarado</th><th>entropia</th></tr></thead>\n<tbody>\n");
        if (result.findings().isEmpty()) {
            out.append("<tr><td colspan=\"6\">nenhum segredo encontrado</td></tr>\n");
        } else {
            for (Finding finding : result.findings()) {
                out.append("<tr><td>").append(escape(finding.path()))
                        .append("</td><td>").append(finding.line())
                        .append("</td><td>").append(escape(finding.rule()))
                        .append("</td><td><span class=\"sev ").append(finding.severity())
                        .append("\">").append(finding.severity()).append("</span>")
                        .append("</td><td><code>").append(escape(finding.maskedValue()))
                        .append("</code></td><td>").append(String.format(Locale.ROOT, "%.2f", finding.entropy()))
                        .append("</td></tr>\n");
            }
        }
        out.append("</tbody>\n</table>\n</body>\n</html>\n");
        return out.toString();
    }

    private static String markdown(ScanResult result) {
        StringBuilder out = new StringBuilder();
        out.append("# SecretSentinel - relatorio\n\n");
        out.append("- arquivos analisados: ").append(result.filesScanned()).append('\n');
        out.append("- tempo de scan: ").append(result.durationMillis()).append(" ms\n");
        out.append("- achados: ").append(result.findings().size()).append('\n');
        out.append("- criticos: ").append(result.count(Severity.CRITICAL)).append('\n');
        out.append("- altos: ").append(result.count(Severity.HIGH)).append('\n');
        out.append("- medios: ").append(result.count(Severity.MEDIUM)).append("\n\n");

        out.append("| arquivo | linha | regra | severidade | valor mascarado | entropia |\n");
        out.append("| --- | ---: | --- | --- | --- | ---: |\n");
        if (result.findings().isEmpty()) {
            out.append("| - | - | - | - | nenhum segredo encontrado | - |\n");
        } else {
            for (Finding finding : result.findings()) {
                out.append('|').append(cell(finding.path()))
                        .append('|').append(finding.line())
                        .append('|').append(cell(finding.rule()))
                        .append('|').append(finding.severity())
                        .append('|').append(cell("`" + finding.maskedValue() + "`"))
                        .append('|').append(String.format(Locale.ROOT, "%.2f", finding.entropy()))
                        .append("|\n");
            }
        }
        return out.toString();
    }

    private static String card(String label, String value, String cssClass) {
        return "<div class=\"card " + cssClass + "\"><span>" + label + "</span><strong>"
                + escape(value) + "</strong></div>\n";
    }

    private static String cell(String value) {
        String safe = OutputSanitizer.clean(value)
                .replace("\\", "\\\\")
                .replace("|", "\\|")
                .replace("`", "\\`")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
        return " " + safe + " ";
    }

    private static String escape(String value) {
        return OutputSanitizer.clean(value)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
