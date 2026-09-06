package edu.hofstra.csc17.proj.soclog.ingest.parser;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import edu.hofstra.csc17.proj.soclog.model.entity.FileInfo;
import edu.hofstra.csc17.proj.soclog.model.entity.NetworkInfo;
import edu.hofstra.csc17.proj.soclog.model.entity.ProcessInfo;
import edu.hofstra.csc17.proj.soclog.model.event.CloseEvent;
import edu.hofstra.csc17.proj.soclog.model.event.Event;
import edu.hofstra.csc17.proj.soclog.model.event.EventType;
import edu.hofstra.csc17.proj.soclog.model.event.ExecuteEvent;
import edu.hofstra.csc17.proj.soclog.model.event.ForkEvent;
import edu.hofstra.csc17.proj.soclog.model.event.OpenEvent;
import edu.hofstra.csc17.proj.soclog.model.event.ReadEvent;
import edu.hofstra.csc17.proj.soclog.model.event.ReceiveFromEvent;
import edu.hofstra.csc17.proj.soclog.model.event.SendToEvent;
import edu.hofstra.csc17.proj.soclog.model.event.WriteEvent;

public class EventParser {

    public static final class ParseResult {
        private final List<Event> events;
        private final List<String> errors;

        public ParseResult(List<Event> events, List<String> errors) {
            this.events = events;
            this.errors = errors;
        }

        public List<Event> getEvents() {
            return events;
        }

        public List<String> getErrors() {
            return errors;
        }
    }

    public ParseResult parse(Path path) throws IOException {
        List<Event> events = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        Instant lastTimestamp = null;

        try (BufferedReader reader = Files.newBufferedReader(path)) {
            String line;
            long lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;

                // Skip empty lines
                if (line.trim().isEmpty()) {
                    continue;
                }

                // Skip header line
                if (lineNumber == 1 && line.startsWith("event_type")) {
                    continue;
                }

                try {
                    Event event = parseLine(line, lastTimestamp);
                    events.add(event);
                    lastTimestamp = event.getTimestamp();
                } catch (Exception e) {
                    errors.add("Line " + lineNumber + ": " + e.getMessage());
                }
            }
        }
        return new ParseResult(events, errors);
    }

    private Event parseLine(String line, Instant lastTimestamp) {
        // CSV format: event_type,event_timestamp,event_flags,event_subject,event_object
        String[] fields = line.split(",", 5);
        if (fields.length != 5) {
            throw new IllegalArgumentException("Expected 5 fields, got " + fields.length);
        }

        // Parse event type (case-insensitive)
        EventType eventType;
        try {
            eventType = EventType.valueOf(fields[0].trim().toLowerCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid event type: " + fields[0]);
        }

        // Parse timestamp
        Instant timestamp;
        try {
            timestamp = Instant.parse(fields[1].trim());
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException("Invalid timestamp format: " + fields[1]);
        }

        // Validate chronological order
        if (lastTimestamp != null && timestamp.isBefore(lastTimestamp)) {
            throw new IllegalArgumentException("Out-of-order timestamp: " + timestamp + " is before " + lastTimestamp);
        }

        String flags = fields[2].trim();
        String subjectStr = fields[3].trim();
        String objectStr = fields[4].trim();

        // Parse subject (always ProcessInfo)
        ProcessInfo subject = parseProcessInfo(subjectStr);

        // Create appropriate event based on type
        switch (eventType) {
            case read:
                return new ReadEvent(timestamp, subject, parseFileInfo(objectStr), flags);
            case write:
                return new WriteEvent(timestamp, subject, parseFileInfo(objectStr), flags);
            case execute:
                return new ExecuteEvent(timestamp, subject, parseFileInfo(objectStr), flags);
            case open:
                return new OpenEvent(timestamp, subject, parseFileInfo(objectStr), flags);
            case close:
                return new CloseEvent(timestamp, subject, parseFileInfo(objectStr), flags);
            case sendto:
                return new SendToEvent(timestamp, subject, parseNetworkInfo(objectStr), flags);
            case receivefrom:
                return new ReceiveFromEvent(timestamp, subject, parseNetworkInfo(objectStr), flags);
            case fork:
                return new ForkEvent(timestamp, subject, parseProcessInfo(objectStr), flags);
            default:
                throw new IllegalArgumentException("Unsupported event type: " + eventType);
        }
    }

    private ProcessInfo parseProcessInfo(String str) {
        Map<String, String> fields = parseKeyValuePairs(str);

        String name = fields.get("name");
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("Missing required field: name");
        }

        String pidStr = fields.get("pid");
        if (pidStr == null || pidStr.isEmpty()) {
            throw new IllegalArgumentException("Missing required field: pid");
        }
        Integer pid;
        try {
            pid = Integer.parseInt(pidStr);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid PID format: " + pidStr);
        }

        String path = fields.get("path");
        if (path == null || path.isEmpty()) {
            throw new IllegalArgumentException("Missing required field: path");
        }

        String privilege = fields.get("privilege");
        if (privilege == null || privilege.isEmpty()) {
            throw new IllegalArgumentException("Missing required field: privilege");
        }

        return new ProcessInfo(name, pid, path, privilege);
    }

    private FileInfo parseFileInfo(String str) {
        Map<String, String> fields = parseKeyValuePairs(str);

        String path = fields.get("path");
        if (path == null || path.isEmpty()) {
            throw new IllegalArgumentException("Missing required field: path");
        }

        String fdStr = fields.get("fd");
        if (fdStr == null || fdStr.isEmpty()) {
            throw new IllegalArgumentException("Missing required field: fd");
        }
        Integer fd;
        try {
            fd = Integer.parseInt(fdStr);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid fd format: " + fdStr);
        }

        String permissions = fields.get("permissions");
        if (permissions == null || permissions.isEmpty()) {
            throw new IllegalArgumentException("Missing required field: permissions");
        }

        return new FileInfo(path, fd, permissions);
    }

    private NetworkInfo parseNetworkInfo(String str) {
        Map<String, String> fields = parseKeyValuePairs(str);

        String ip = fields.get("ip");
        if (ip == null || ip.isEmpty()) {
            throw new IllegalArgumentException("Missing required field: ip");
        }

        String portStr = fields.get("port");
        if (portStr == null || portStr.isEmpty()) {
            throw new IllegalArgumentException("Missing required field: port");
        }
        Integer port;
        try {
            port = Integer.parseInt(portStr);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid port format: " + portStr);
        }

        String protocol = fields.get("protocol");
        if (protocol == null || protocol.isEmpty()) {
            throw new IllegalArgumentException("Missing required field: protocol");
        }

        return new NetworkInfo(ip, port, protocol);
    }

    private Map<String, String> parseKeyValuePairs(String str) {
        Map<String, String> result = new HashMap<>();
        if (str == null || str.isEmpty()) {
            return result;
        }

        String[] pairs = str.split(";");
        for (String pair : pairs) {
            if (pair.trim().isEmpty()) {
                continue;
            }
            String[] kv = pair.split("=", 2);
            if (kv.length != 2) {
                throw new IllegalArgumentException("Malformed key=value pair: " + pair);
            }
            result.put(kv[0].trim(), kv[1].trim());
        }
        return result;
    }
}
