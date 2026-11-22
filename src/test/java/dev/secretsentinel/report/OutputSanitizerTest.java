package dev.secretsentinel.report;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class OutputSanitizerTest {

    @Test
    void neutralizaEscapeANSI() {
        assertEquals("a?[31mb", OutputSanitizer.clean("a\u001B[31mb"));
    }

    @Test
    void neutralizaControlesBidiEQuebras() {
        assertEquals("??", OutputSanitizer.clean("\u202A\u2066"));
        assertEquals("linha?", OutputSanitizer.clean("linha\n"));
    }

    @Test
    void textoComumPassaSemAlteracao() {
        assertEquals("AKIA************9X2A", OutputSanitizer.clean("AKIA************9X2A"));
        assertEquals("", OutputSanitizer.clean(null));
    }
}
