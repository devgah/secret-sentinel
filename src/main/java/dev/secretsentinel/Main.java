package dev.secretsentinel;

import dev.secretsentinel.cli.CliArguments;
import dev.secretsentinel.cli.CliParser;
import dev.secretsentinel.cli.ConsoleView;
import dev.secretsentinel.model.ScanResult;
import dev.secretsentinel.report.OutputSanitizer;
import dev.secretsentinel.report.ReportWriter;
import dev.secretsentinel.scanner.DirectoryScanner;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

public final class Main {

    private Main() {
    }

    public static void main(String[] args) {
        if (List.of(args).contains("--help") || List.of(args).contains("-h")) {
            System.out.println(CliParser.usage());
            return;
        }

        CliArguments options;
        try {
            options = CliParser.parse(args);
        } catch (IllegalArgumentException e) {
            System.err.println("erro: " + OutputSanitizer.clean(e.getMessage()));
            System.err.println(CliParser.usage());
            System.exit(2);
            return;
        }

        ConsoleView.printBanner();

        try {
            ScanResult result = new DirectoryScanner(options.entropyThreshold()).scan(options.path());
            ConsoleView.printSummary(result, options.path());

            if (options.format() != CliArguments.ReportFormat.NONE) {
                String extension = switch (options.format()) {
                    case HTML -> "html";
                    case MD -> "md";
                    case NONE -> "";
                };
                Path output = options.output() != null
                        ? options.output()
                        : Path.of("secret-sentinel-report." + extension);
                ReportWriter.write(result, options.format(), output);
                ConsoleView.printReportPath(output);
            }

            System.exit(result.findings().isEmpty() ? 0 : 1);
        } catch (IOException e) {
            System.err.println("erro: " + OutputSanitizer.clean(e.getMessage()));
            System.exit(2);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("erro: varredura interrompida");
            System.exit(2);
        }
    }
}
