package dev.secretsentinel.scanner;

import dev.secretsentinel.model.ScanResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertTrue;

class DirectoryScannerTest {

    @TempDir
    Path temp;

    @Test
    void byteInvalidoNaoOcultaSegredoDepois() throws Exception {
        byte[] prefix = {(byte) 0xFF, (byte) 0xFE};
        byte[] secret = "api_key=Sup3rS3cret\n".getBytes(StandardCharsets.UTF_8);
        Path file = temp.resolve("mixed.txt");
        Files.write(file, join(prefix, secret));

        ScanResult result = new DirectoryScanner(4.5).scan(temp);

        assertTrue(result.findings().stream()
                .anyMatch(finding -> finding.rule().equals("HARDCODED_SECRET")));
    }

    @Test
    void umNuloNaoDescartaArquivoTextual() throws Exception {
        byte[] secret = "api_key=Sup3rS3cret\n".getBytes(StandardCharsets.UTF_8);
        Path file = temp.resolve("null.txt");
        Files.write(file, join(new byte[]{0}, secret));

        ScanResult result = new DirectoryScanner(4.5).scan(temp);

        assertTrue(result.findings().stream()
                .anyMatch(finding -> finding.rule().equals("HARDCODED_SECRET")));
    }

    @Test
    void arquivoComMuitosNulosEIgnorado() throws Exception {
        Path file = temp.resolve("bin.txt");
        byte[] bytes = new byte[64];
        Arrays.fill(bytes, (byte) 0);
        Files.write(file, bytes);

        ScanResult result = new DirectoryScanner(4.5).scan(temp);

        assertTrue(result.findings().isEmpty());
    }

    private static byte[] join(byte[] first, byte[] second) {
        byte[] joined = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, joined, first.length, second.length);
        return joined;
    }
}
