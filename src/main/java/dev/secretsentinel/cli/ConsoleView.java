package dev.secretsentinel.cli;

import dev.secretsentinel.model.Finding;
import dev.secretsentinel.model.ScanResult;
import dev.secretsentinel.model.Severity;
import dev.secretsentinel.report.OutputSanitizer;

import java.nio.file.Path;

public final class ConsoleView {

    private static final String RESET = "\u001B[0m";
    private static final String BOLD = "\u001B[1m";
    private static final String RED = "\u001B[31m";
    private static final String YELLOW = "\u001B[33m";
    private static final String CYAN = "\u001B[36m";
    private static final String GREEN = "\u001B[32m";

    private ConsoleView() {
    }

    public static void printBanner() {
        System.out.println("""
                   ____             _   _             _   _   ____  _____ ____  _____
                  / ___|  ___ _ __ | |_(_)_   _____ | | | | / ___|| ____|  _ \\| ____|
                  \\___ \\ / _ \\ '_ \\| __| \\ \\ / / _ \\| | | | \\___ \\|  _| | |_) |  _|
                   ___) |  __/ |_) | |_| |\\ V /  __/| |_| |  ___) | |___|  _ <| |___
                  |____/ \\___| .__/ \\__|_| \\_/ \\___| \\___/  |____/|_____|_| \\_\\_____|
                               |_|
                """.stripTrailing());
        System.out.println("secret sentinel - devsecops secret scanner");
        System.out.println();
    }

    public static void printSummary(ScanResult result, Path root) {
        System.out.println("diretorio: " + OutputSanitizer.clean(root.toAbsolutePath().normalize().toString()));
        System.out.println("arquivos analisados: " + result.filesScanned());
        System.out.println("tempo de scan: " + result.durationMillis() + " ms");
        System.out.println();

        if (result.findings().isEmpty()) {
            System.out.println(GREEN + BOLD + "nenhum segredo encontrado" + RESET);
            return;
        }

        System.out.println(BOLD + "achados: " + result.findings().size() + RESET);
        for (Finding finding : result.findings()) {
            String color = colorFor(finding.severity());
            System.out.printf("%s%-8s%s %s:%d [%s] %s (entropia: %.2f)%n",
                    color, finding.severity(), RESET,
                    OutputSanitizer.clean(finding.path()), finding.line(),
                    OutputSanitizer.clean(finding.rule()),
                    OutputSanitizer.clean(finding.maskedValue()), finding.entropy());
        }
        System.out.println();
        System.out.printf("criticos: %s%d%s | altos: %s%d%s | medios: %s%d%s%n",
                RED, result.count(Severity.CRITICAL), RESET,
                YELLOW, result.count(Severity.HIGH), RESET,
                CYAN, result.count(Severity.MEDIUM), RESET);
    }

    public static void printReportPath(Path output) {
        System.out.println("relatorio: " + OutputSanitizer.clean(output.toAbsolutePath().normalize().toString()));
    }

    private static String colorFor(Severity severity) {
        return switch (severity) {
            case CRITICAL -> RED;
            case HIGH -> YELLOW;
            case MEDIUM -> CYAN;
        };
    }
}
