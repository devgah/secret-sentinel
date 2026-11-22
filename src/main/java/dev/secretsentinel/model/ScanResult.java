package dev.secretsentinel.model;

import java.util.List;

public record ScanResult(List<Finding> findings, int filesScanned, long durationMillis) {

    public ScanResult {
        findings = List.copyOf(findings);
    }

    public long count(Severity severity) {
        return findings.stream().filter(finding -> finding.severity() == severity).count();
    }
}
