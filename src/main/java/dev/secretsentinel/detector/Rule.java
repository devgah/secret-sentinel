package dev.secretsentinel.detector;

import dev.secretsentinel.model.Severity;

import java.util.regex.Pattern;

record Rule(String name, Pattern pattern, Severity severity, int valueGroup) {
}
