package edu.hofstra.csc17.proj.soclog;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import edu.hofstra.csc17.proj.soclog.analysis.AnalyticsEngine;
import edu.hofstra.csc17.proj.soclog.ingest.LogIngestor;
import edu.hofstra.csc17.proj.soclog.ingest.parser.EventParser;
import edu.hofstra.csc17.proj.soclog.ioc.index.InvertedIndex;
import edu.hofstra.csc17.proj.soclog.ioc.model.IOC;
import edu.hofstra.csc17.proj.soclog.ioc.model.IOCType;
import edu.hofstra.csc17.proj.soclog.ioc.model.ThreatReport;
import edu.hofstra.csc17.proj.soclog.model.event.Event;

import java.util.Map;

public final class Main {

    public static void main(String[] args) throws Exception {
        List<Path> inputs;

        if (args.length == 0) {
            // Default to data directory if no arguments provided
            System.out.println("No arguments provided. Using default 'data' directory...");
            inputs = getCsvFilesFromDirectory(Paths.get("data"));
        } else if (args.length == 1) {
            Path arg = Paths.get(args[0]);
            if (Files.isDirectory(arg)) {
                // Single argument is a directory - process all CSV files in it
                System.out.println("Processing all CSV files in directory: " + arg);
                inputs = getCsvFilesFromDirectory(arg);
            } else {
                // Single argument is a file
                inputs = Arrays.asList(arg);
            }
        } else {
            // Multiple arguments - treat as individual files
            inputs = Arrays.stream(args)
                    .map(Paths::get)
                    .collect(Collectors.toList());
        }

        if (inputs.isEmpty()) {
            System.err.println("No CSV files found to process.");
            printUsage();
            System.exit(1);
        }

        System.out.println("Processing " + inputs.size() + " CSV file(s):");
        for (Path input : inputs) {
            System.out.println("  - " + input);
        }

        LogIngestor ingestor = new LogIngestor(new EventParser());
        LogIngestor.IngestionResult summary = ingestor.ingest(inputs);

        System.out.println("Valid events: " + summary.getEvents().size());
        System.out.println("Rejections: " + summary.getErrors().size());
        if (!summary.getErrors().isEmpty()) {
            System.out.println("Sample rejection: " + summary.getErrors().get(0));
        }

        // Demonstrate analytics functionality
        AnalyticsEngine engine = new AnalyticsEngine(summary.getEvents());
        System.out.println();
        System.out.println("\n=== Threat Intelligence Demo ===");

        // Demonstrate IOC threat intelligence
        demonstrateThreatIntelligence(engine);
    }


    private static void demonstrateThreatIntelligence(AnalyticsEngine engine) {
        try {
            // Step 1: Load threat intelligence reports
            System.out.println("\nStep 1: Loading threat intelligence reports...");
            Path threatReportsPath = Paths.get("data/threat_reports.csv");

            if (!Files.exists(threatReportsPath)) {
                System.out.println("  ! Threat reports file not found: " + threatReportsPath);
                return;
            }

            List<ThreatReport> reports = AnalyticsEngine.loadThreatReports(threatReportsPath);
            System.out.println("  ✓ Loaded " + reports.size() + " threat reports");

            System.out.println("\n=== Threat Report Summary ===");
            for (ThreatReport report : reports) {
                System.out.println("\nReport: " + report.getReportId());
                System.out.println("  Actor: " + report.getThreatActor());
                System.out.println("  Severity: " + report.getSeverity());
                System.out.println("  IOCs: " + report.getIocs().size());
                System.out.println("  Description: " + report.getDescription());
            }

            // Step 2: Extract IOCs from threat reports
            System.out.println("\nStep 2: Extracting IOCs from threat reports...");
            List<IOC> knownIOCs = AnalyticsEngine.extractIOCsFromReports(reports);
            System.out.println("  ✓ Extracted " + knownIOCs.size() + " known IOCs");

            // Show IOC breakdown by type
            Map<IOCType, Integer> iocStats = new java.util.HashMap<>();
            for (IOC ioc : knownIOCs) {
                iocStats.put(ioc.getType(), iocStats.getOrDefault(ioc.getType(), 0) + 1);
            }

            System.out.println("\n  IOCs by type:");
            for (Map.Entry<IOCType, Integer> entry : iocStats.entrySet()) {
                System.out.println("    - " + entry.getKey() + ": " + entry.getValue());
            }

            // Step 3: Scan events for known IOCs using AnalyticsEngine
            System.out.println("\nStep 3: Scanning events for known IOCs...");
            Map<Event, List<IOC>> matches = engine.scanForThreats(knownIOCs);

            System.out.println("  ✓ Found " + matches.size() + " events matching known IOCs");

            // Step 4: Display threat detections
            if (!matches.isEmpty()) {
                System.out.println("\n=== THREAT DETECTIONS ===");
                int displayCount = 0;
                for (Map.Entry<Event, List<IOC>> entry : matches.entrySet()) {
                    Event event = entry.getKey();
                    List<IOC> eventMatches = entry.getValue();

                    System.out.println("\nThreat Event #" + (++displayCount) + ":");
                    System.out.println("  Time: " + event.getTimestamp());
                    System.out.println("  Type: " + event.getType());
                    System.out.println("  Process: " + event.getSubject().getName() +
                                     " (PID: " + event.getSubject().getPid() + ")");
                    System.out.println("  Matched IOCs:");
                    for (IOC match : eventMatches) {
                        System.out.println("    - " + match.getType() + ": " + match.getValue() +
                                         " [" + match.getSource() + "]");
                    }

                    if (displayCount >= 5) {
                        int remaining = matches.size() - displayCount;
                        if (remaining > 0) {
                            System.out.println("\n  ... and " + remaining + " more threat events");
                        }
                        break;
                    }
                }
            } else {
                System.out.println("\n  ✓ No threats detected in event logs");
            }

            // Step 5: Demonstrate InvertedIndex for fast lookups
            System.out.println("\n=== InvertedIndex & Trie Demo ===");

            // Build inverted index using AnalyticsEngine
            InvertedIndex index = engine.buildThreatIntelligenceIndex(reports);

            System.out.println("\nStep 5a: Building inverted index...");
            System.out.println("  ✓ Indexed " + index.getReportCount() + " threat reports");
            System.out.println("  ✓ Total unique IOCs: " + index.getUniqueIOCCount());

            // Demonstrate O(1) exact lookup
            System.out.println("\nStep 5b: Fast O(1) exact IOC lookup...");
            IOC testIOC = new IOC("192.168.1.100", IOCType.IP_ADDRESS);
            List<ThreatReport> foundReports = index.searchExact(testIOC);
            if (!foundReports.isEmpty()) {
                System.out.println("  ✓ Found IOC '192.168.1.100' in " + foundReports.size() + " report(s):");
                for (ThreatReport r : foundReports) {
                    System.out.println("    - " + r.getReportId() + ": " + r.getDescription());
                }
            }

            // Demonstrate Trie-based prefix search
            System.out.println("\nStep 5c: Trie-based prefix search...");
            List<ThreatReport> prefixMatches = index.searchPrefix("192.168.", IOCType.IP_ADDRESS);
            System.out.println("  ✓ Found " + prefixMatches.size() + " report(s) with IPs matching '192.168.*'");

            // Demonstrate subnet analysis
            System.out.println("\nStep 5d: Subnet analysis...");
            List<Event> subnetEvents = engine.findEventsInSubnet("192.168.");
            System.out.println("  ✓ Found " + subnetEvents.size() + " events in 192.168.0.0/16 subnet");

            // Demonstrate bulk IOC search
            System.out.println("\nStep 5e: Bulk IOC search...");
            List<IOC> sampleIOCs = knownIOCs.subList(0, Math.min(5, knownIOCs.size()));
            Map<IOC, List<ThreatReport>> bulkResults = index.searchBatch(sampleIOCs);
            for (IOC ioc : sampleIOCs) {
                List<ThreatReport> reportsForIOC = bulkResults.get(ioc);
                System.out.println("    - IOC " + ioc.getValue() + " found in " +
                                   (reportsForIOC != null ? reportsForIOC.size() : 0) + " report(s)");
            }


        } catch (IOException e) {
            System.err.println("Error loading threat intelligence: " + e.getMessage());
        }
    }

    /**
     * Get all CSV files from the given directory.
     */
    private static List<Path> getCsvFilesFromDirectory(Path directory) throws IOException {
        List<Path> csvFiles = new ArrayList<>();

        if (!Files.exists(directory)) {
            System.err.println("Directory does not exist: " + directory);
            return csvFiles;
        }

        if (!Files.isDirectory(directory)) {
            System.err.println("Path is not a directory: " + directory);
            return csvFiles;
        }

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(directory, "*.csv")) {
            for (Path file : stream) {
                csvFiles.add(file);
            }
        }

        if (csvFiles.isEmpty()) {
            System.out.println("No CSV files found in directory: " + directory);
        } else {
            System.out.println("Found " + csvFiles.size() + " CSV file(s) in " + directory);
        }

        return csvFiles;
    }

    /**
     * Print usage information.
     */
    private static void printUsage() {
        System.err.println("Usage:");
        System.err.println("  java edu.hofstra.csc17.proj.soclog.Main");
        System.err.println("    (processes all CSV files in 'data' directory)");
        System.err.println("  java edu.hofstra.csc17.proj.soclog.Main <directory>");
        System.err.println("    (processes all CSV files in specified directory)");
        System.err.println("  java edu.hofstra.csc17.proj.soclog.Main <csv-file> [<csv-file>...]");
        System.err.println("    (processes specified CSV files)");
        System.err.println();
        System.err.println("Examples:");
        System.err.println("  java edu.hofstra.csc17.proj.soclog.Main");
        System.err.println("  java edu.hofstra.csc17.proj.soclog.Main data");
        System.err.println("  java edu.hofstra.csc17.proj.soclog.Main /path/to/logs");
        System.err.println("  java edu.hofstra.csc17.proj.soclog.Main file1.csv file2.csv");
    }

    private Main() {
    }
}
