package dev.secretsentinel.detector;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ShannonEntropyTest {

    @Test
    void stringConstanteTemEntropiaZero() {
        assertEquals(0.0, ShannonEntropy.calculate("aaaaaaaa"), 1e-9);
    }

    @Test
    void vaziaEZero() {
        assertEquals(0.0, ShannonEntropy.calculate(""), 1e-9);
        assertEquals(0.0, ShannonEntropy.calculate(null), 1e-9);
    }

    @Test
    void doisSimbolosEquiprovaveisDaoUmBit() {
        assertEquals(1.0, ShannonEntropy.calculate("ababab"), 1e-9);
    }

    @Test
    void quatroSimbolosEquiprovaveisDaoDoisBits() {
        assertEquals(2.0, ShannonEntropy.calculate("abcdabcd"), 1e-9);
    }

    @Test
    void distribuicaoDesigualTemEntropiaMenorQueONumeroDeSimbolos() {
        double entropy = ShannonEntropy.calculate("aaab");
        assertTrue(entropy > 0.0 && entropy < 2.0);
    }

    @Test
    void tokenAleatorioPassaDoLimitePadrao() {
        String token = "aB3xY7qL2pR9sT4vW8zK5mN1";
        assertTrue(ShannonEntropy.calculate(token) > 4.5);
    }
}
