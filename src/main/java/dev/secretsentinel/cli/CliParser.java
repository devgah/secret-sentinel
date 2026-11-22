package dev.secretsentinel.cli;

import dev.secretsentinel.report.OutputSanitizer;

import java.nio.file.Path;
import java.util.Locale;

public final class CliParser {

    private static final double DEFAULT_ENTROPY = 4.5;

    private CliParser() {
    }

    public static CliArguments parse(String[] args) {
        Path path = null;
        CliArguments.ReportFormat format = CliArguments.ReportFormat.HTML;
        Path output = null;
        double entropy = DEFAULT_ENTROPY;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--path" -> path = Path.of(value(args, ++i, "--path"));
                case "--format" -> format = parseFormat(value(args, ++i, "--format"));
                case "--output" -> output = Path.of(value(args, ++i, "--output"));
                case "--entropy" -> entropy = parseEntropy(value(args, ++i, "--entropy"));
                default -> throw new IllegalArgumentException("argumento desconhecido: " + OutputSanitizer.clean(args[i]));
            }
        }

        if (path == null) {
            throw new IllegalArgumentException("--path e obrigatorio");
        }
        return new CliArguments(path, format, output, entropy);
    }

    public static String usage() {
        return """
                uso: secret-sentinel --path <diretorio> [opcoes]

                opcoes:
                  --path <diretorio>   diretorio ou repositorio a verificar (obrigatorio)
                  --format <formato>   html, md ou none (padrao: html)
                  --output <arquivo>   caminho do relatorio (padrao: secret-sentinel-report.<formato>)
                  --entropy <valor>    limite de entropia de 0 a 16 (padrao: 4.5)
                  --help               exibe esta ajuda

                codigos de saida: 0 = limpo, 1 = segredos encontrados, 2 = erro de uso ou leitura""";
    }

    private static String value(String[] args, int index, String flag) {
        if (index >= args.length) {
            throw new IllegalArgumentException("valor ausente para " + flag);
        }
        return args[index];
    }

    private static CliArguments.ReportFormat parseFormat(String raw) {
        return switch (raw.toLowerCase(Locale.ROOT)) {
            case "html" -> CliArguments.ReportFormat.HTML;
            case "md", "markdown" -> CliArguments.ReportFormat.MD;
            case "none" -> CliArguments.ReportFormat.NONE;
            default -> throw new IllegalArgumentException("formato invalido: " + OutputSanitizer.clean(raw) + " (use html, md ou none)");
        };
    }

    private static double parseEntropy(String raw) {
        double value;
        try {
            value = Double.parseDouble(raw);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("entropia invalida: " + OutputSanitizer.clean(raw), e);
        }
        if (Double.isNaN(value) || value <= 0 || value > 16) {
            throw new IllegalArgumentException("entropia fora do intervalo: " + OutputSanitizer.clean(raw));
        }
        return value;
    }
}
