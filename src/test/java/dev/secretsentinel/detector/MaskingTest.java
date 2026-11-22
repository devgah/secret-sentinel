package dev.secretsentinel.detector;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class MaskingTest {

    @Test
    void mascaraChaveAwsMantendoPrefixoSufixo() {
        assertEquals("AKIA************9X2A", Masking.mask("AKIA1234567890129X2A"));
    }

    @Test
    void valorCurtoNaoDevolveQuaseOMensagemOriginal() {
        assertEquals("a****c", Masking.mask("abc"));
        assertEquals("s******3", Masking.mask("senha123"));
        assertFalse(Masking.mask("Sup3rS3cret").contains("Sup3"));
    }

    @Test
    void valorMedioMostraApenasDuasPontas() {
        assertEquals("Su*********AB", Masking.mask("Sup3rS3cretAB"));
    }

    @Test
    void valorLongoLimitaAsteriscos() {
        String masked = Masking.mask("x".repeat(100));
        assertEquals("xxxx************xxxx", masked);
    }

    @Test
    void valorVazio() {
        assertEquals("", Masking.mask(""));
        assertEquals("", Masking.mask(null));
    }
}
