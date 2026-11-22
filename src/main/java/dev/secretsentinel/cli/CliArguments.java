package dev.secretsentinel.cli;

import java.nio.file.Path;

public record CliArguments(Path path, ReportFormat format, Path output, double entropyThreshold) {

    public enum ReportFormat {
        HTML, MD, NONE
    }
}
