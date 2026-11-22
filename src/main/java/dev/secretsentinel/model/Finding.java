package dev.secretsentinel.model;

public record Finding(String path, int line, String rule, Severity severity, String maskedValue, double entropy) {
}
