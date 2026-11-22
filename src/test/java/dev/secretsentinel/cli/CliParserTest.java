package dev.secretsentinel.cli;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CliParserTest {

    @Test
    void usaPadroesQuandoSoOPathEInformado() {
        CliArguments args = CliParser.parse(new String[]{"--path", "demo-repo"});
        assertEquals(Path.of("demo-repo"), args.path());
        assertEquals(CliArguments.ReportFormat.HTML, args.format());
        assertNull(args.output());
        assertEquals(4.5, args.entropyThreshold());
    }

    @Test
    void leTodasAsOpcoes() {
        CliArguments args = CliParser.parse(new String[]{
                "--path", ".", "--format", "md", "--output", "relatorio.md", "--entropy", "5.2"});
        assertEquals(CliArguments.ReportFormat.MD, args.format());
        assertEquals(Path.of("relatorio.md"), args.output());
        assertEquals(5.2, args.entropyThreshold());
    }

    @Test
    void exigePath() {
        assertThrows(IllegalArgumentException.class, () -> CliParser.parse(new String[]{"--format", "md"}));
    }

    @Test
    void rejeitaFormatoEEntropiaInvalidos() {
        assertThrows(IllegalArgumentException.class,
                () -> CliParser.parse(new String[]{"--path", ".", "--format", "pdf"}));
        assertThrows(IllegalArgumentException.class,
                () -> CliParser.parse(new String[]{"--path", ".", "--entropy", "abc"}));
    }
}
