package edu.hofstra.csc17.proj.soclog.ingest;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import edu.hofstra.csc17.proj.soclog.ingest.parser.EventParser;
import edu.hofstra.csc17.proj.soclog.model.event.Event;

public class LogIngestor {
    private final EventParser parser;

    public LogIngestor(EventParser parser) {
        this.parser = parser;
    }

    public IngestionResult ingest(List<Path> logFiles) throws IOException {
        List<Event> events = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        for (Path file : logFiles) {
            if (!Files.exists(file)) {
                errors.add("Missing file: " + file);
                continue;
            }
            EventParser.ParseResult parsed = parser.parse(file);
            events.addAll(parsed.getEvents());
            errors.addAll(parsed.getErrors());
        }
        return new IngestionResult(events, errors);
    }

    public static final class IngestionResult {
        private final List<Event> events;
        private final List<String> errors;

        public IngestionResult(List<Event> events, List<String> errors) {
            this.events = events;
            this.errors = errors;
        }

        public List<Event> getEvents() {
            return events;
        }

        public List<String> getErrors() {
            return errors;
        }

        public void printIngestionSummary() {
            System.out.println("Ingestion Summary:");
            System.out.println("  Valid events: " + events.size());
            System.out.println("  Rejections: " + errors.size());
            System.out.println("  Processing time: " + "..." + " ms");
        }

    }
}
