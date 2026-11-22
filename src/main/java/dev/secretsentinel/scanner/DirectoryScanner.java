package dev.secretsentinel.scanner;

import dev.secretsentinel.detector.DetectionEngine;
import dev.secretsentinel.model.Finding;
import dev.secretsentinel.model.ScanResult;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

public final class DirectoryScanner {

    private static final Set<String> IGNORED_DIRS = Set.of(
            ".git", "node_modules", "target", "build", ".idea", ".vscode", "dist", "out");
    private static final Set<String> IGNORED_EXTENSIONS = Set.of(
            ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
            ".pdf", ".jar", ".war", ".ear", ".class", ".exe", ".dll", ".so", ".dylib",
            ".bin", ".zip", ".gz", ".tar", ".7z", ".rar", ".mp3", ".mp4", ".mov", ".avi",
            ".woff", ".woff2", ".ttf", ".eot", ".otf", ".db", ".sqlite", ".dat");
    private static final Set<String> IGNORED_FILES = Set.of(
            "package-lock.json", "yarn.lock", "pnpm-lock.yaml");
    private static final long MAX_FILE_BYTES = 2L * 1024 * 1024;
    private static final int MAX_LINE_LENGTH = 64 * 1024;
    private static final int MAX_CONCURRENT_READS = 64;
    private static final int BATCH_SIZE = 512;
    private static final int MAX_FINDINGS_PER_FILE = 200;
    private static final int MAX_FINDINGS = 10_000;

    private final double entropyThreshold;

    public DirectoryScanner(double entropyThreshold) {
        this.entropyThreshold = entropyThreshold;
    }

    // a caminhada consome o stream em lotes, sem manter todas as paths na memoria
    public ScanResult scan(Path root) throws IOException, InterruptedException {
        long start = System.currentTimeMillis();
        DetectionEngine engine = new DetectionEngine(entropyThreshold);
        AtomicInteger filesScanned = new AtomicInteger();
        List<Finding> findings = new ArrayList<>();
        Semaphore slots = new Semaphore(MAX_CONCURRENT_READS);

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
             Stream<Path> paths = Files.walk(root)) {
            Iterator<Path> iterator = paths.filter(Files::isRegularFile)
                    .filter(path -> !Files.isSymbolicLink(path))
                    .filter(DirectoryScanner::isScannable)
                    .iterator();

            List<Path> batch = new ArrayList<>(BATCH_SIZE);
            while (iterator.hasNext()) {
                batch.add(iterator.next());
                if (batch.size() < BATCH_SIZE) {
                    continue;
                }
                runBatch(root, batch, executor, slots, engine, filesScanned, findings);
                batch.clear();
                if (findings.size() >= MAX_FINDINGS) {
                    break;
                }
            }
            if (!batch.isEmpty() && findings.size() < MAX_FINDINGS) {
                runBatch(root, batch, executor, slots, engine, filesScanned, findings);
            }
        }

        findings.sort(Comparator.comparing(Finding::path)
                .thenComparingInt(Finding::line)
                .thenComparing(Finding::rule));
        return new ScanResult(findings, filesScanned.get(), System.currentTimeMillis() - start);
    }

    private static void runBatch(Path root, List<Path> batch, ExecutorService executor,
                                 Semaphore slots, DetectionEngine engine,
                                 AtomicInteger filesScanned, List<Finding> findings)
            throws IOException, InterruptedException {
        List<Future<List<Finding>>> tasks = new ArrayList<>(batch.size());
        for (Path file : batch) {
            tasks.add(executor.submit(() -> {
                slots.acquire();
                try {
                    return scanFile(root, file, engine, filesScanned);
                } finally {
                    slots.release();
                }
            }));
        }
        for (Future<List<Finding>> task : tasks) {
            try {
                findings.addAll(task.get());
            } catch (ExecutionException e) {
                Throwable cause = e.getCause();
                if (cause instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                    throw new InterruptedException("varredura interrompida");
                }
                throw new IOException("falha ao analisar arquivo", cause);
            }
        }
        if (findings.size() > MAX_FINDINGS) {
            findings.subList(MAX_FINDINGS, findings.size()).clear();
        }
    }

    private static List<Finding> scanFile(Path root, Path file, DetectionEngine engine,
                                          AtomicInteger filesScanned) {
        List<Finding> findings = new ArrayList<>();
        byte[] bytes;
        try {
            if (Files.size(file) > MAX_FILE_BYTES) {
                return findings;
            }
            try (InputStream input = Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS)) {
                bytes = input.readNBytes((int) MAX_FILE_BYTES);
            }
        } catch (IOException e) {
            return findings;
        }
        if (!looksLikeText(bytes)) {
            return findings;
        }

        filesScanned.incrementAndGet();
        String relativePath = root.relativize(file).toString().replace('\\', '/');
        // UTF-8 com substituicao evita que um byte invalido oculte o resto do arquivo
        String content = new String(bytes, StandardCharsets.UTF_8);
        try (BufferedReader reader = new BufferedReader(new StringReader(content))) {
            String line;
            int lineNumber = 1;
            while ((line = reader.readLine()) != null && findings.size() < MAX_FINDINGS_PER_FILE) {
                // linha muito longa pode estourar memoria ou indicar dados binarios
                if (line.length() <= MAX_LINE_LENGTH) {
                    findings.addAll(engine.analyze(relativePath, lineNumber, line));
                }
                lineNumber++;
            }
        } catch (IOException e) {
            return findings;
        }
        return findings;
    }

    private static boolean isScannable(Path path) {
        // nao segue symlinks para nao ler arquivos fora da raiz informada
        if (Files.isSymbolicLink(path)) {
            return false;
        }
        String name = path.getFileName().toString();
        String lowerName = name.toLowerCase(Locale.ROOT);

        for (Path part : path) {
            if (IGNORED_DIRS.contains(part.toString().toLowerCase(Locale.ROOT))) {
                return false;
            }
        }
        if (IGNORED_FILES.contains(lowerName)) {
            return false;
        }
        int dot = lowerName.lastIndexOf('.');
        return dot < 0 || !IGNORED_EXTENSIONS.contains(lowerName.substring(dot));
    }

    private static boolean looksLikeText(byte[] bytes) {
        int sample = Math.min(bytes.length, 1024);
        int nulls = 0;
        for (int i = 0; i < sample; i++) {
            if (bytes[i] == 0) {
                nulls++;
            }
        }
        // um unico nulo nao pode descartar um arquivo textual com segredos
        return nulls * 20 <= sample;
    }
}
