package edu.hofstra.csc17.proj.soclog.ioc;

import edu.hofstra.csc17.proj.soclog.ioc.model.IOC;
import edu.hofstra.csc17.proj.soclog.ioc.model.IOCType;
import edu.hofstra.csc17.proj.soclog.ioc.model.ThreatReport;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Parses threat intelligence reports from CSV files.
 * Loads IOCs from threat intelligence feeds into ThreatReport objects.
 *
 * CSV Format: report_id,timestamp,ioc_type,ioc_value,severity,threat_actor,description
 */
public class ThreatReportParser {

    /**
     * Parses a threat reports CSV file and returns a list of ThreatReport objects.
     * Multiple rows with the same report_id are aggregated into a single ThreatReport.
     *
     * @param csvPath Path to the threat reports CSV file
     * @return List of parsed ThreatReport objects
     * @throws IOException if file cannot be read
     */
    public static List<ThreatReport> parseThreatReports(Path csvPath) throws IOException {
        // Use a map to aggregate IOCs by report_id
        Map<String, ThreatReportBuilder> reportBuilders = new HashMap<>();

        try (BufferedReader reader = Files.newBufferedReader(csvPath)) {
            String line;
            boolean firstLine = true;

            while ((line = reader.readLine()) != null) {
                // Skip header
                if (firstLine) {
                    firstLine = false;
                    continue;
                }

                // Skip empty lines
                if (line.trim().isEmpty()) {
                    continue;
                }

                try {
                    String[] fields = line.split(",");
                    if (fields.length < 7) {
                        System.err.println("Skipping malformed line: " + line);
                        continue;
                    }

                    String reportId = fields[0].trim();
                    Instant timestamp = Instant.parse(fields[1].trim());
                    IOCType iocType = IOCType.valueOf(fields[2].trim());
                    String iocValue = fields[3].trim();
                    String severity = fields[4].trim();
                    String threatActor = fields[5].trim();
                    String description = fields[6].trim();

                    // Get or create builder for this report
                    ThreatReportBuilder builder = reportBuilders.computeIfAbsent(
                        reportId,
                        id -> new ThreatReportBuilder(reportId, timestamp, severity, threatActor, description)
                    );

                    // Add IOC to this report
                    IOC ioc = new IOC(iocValue, iocType, reportId);
                    builder.addIOC(ioc);

                } catch (Exception e) {
                    System.err.println("Error parsing line: " + line + " - " + e.getMessage());
                }
            }
        }

        // Build all reports
        List<ThreatReport> reports = new ArrayList<>();
        for (ThreatReportBuilder builder : reportBuilders.values()) {
            reports.add(builder.build());
        }

        return reports;
    }

    /**
     * Extracts all unique IOCs from a list of threat reports.
     *
     * @param reports List of threat reports
     * @return List of all IOCs across all reports
     */
    public static List<IOC> extractAllIOCs(List<ThreatReport> reports) {
        List<IOC> allIOCs = new ArrayList<>();
        for (ThreatReport report : reports) {
            allIOCs.addAll(report.getIocs());
        }
        return allIOCs;
    }

    /**
     * Helper class to build ThreatReport objects by aggregating multiple CSV rows.
     */
    private static class ThreatReportBuilder {
        private final String reportId;
        private final Instant timestamp;
        private final String severity;
        private final String threatActor;
        private final String description;
        private final List<IOC> iocs;

        public ThreatReportBuilder(String reportId, Instant timestamp, String severity,
                                   String threatActor, String description) {
            this.reportId = reportId;
            this.timestamp = timestamp;
            this.severity = severity;
            this.threatActor = threatActor;
            this.description = description;
            this.iocs = new ArrayList<>();
        }

        public void addIOC(IOC ioc) {
            iocs.add(ioc);
        }

        public ThreatReport build() {
            return new ThreatReport(reportId, timestamp, iocs, threatActor, severity, description);
        }
    }
}
