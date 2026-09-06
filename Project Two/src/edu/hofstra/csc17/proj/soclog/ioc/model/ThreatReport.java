package edu.hofstra.csc17.proj.soclog.ioc.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Represents a threat intelligence report containing multiple IOCs.
 * Reports aggregate related IOCs from security incidents or threat hunting.
 */
public class ThreatReport {
    private final String reportId;
    private final Instant timestamp;
    private final List<IOC> iocs;
    private final String threatActor;
    private final String severity; // HIGH, MEDIUM, LOW
    private final String description;

    /**
     * Creates a new threat report.
     *
     * @param reportId Unique identifier for the report
     * @param timestamp When the report was created or threat was observed
     * @param iocs List of IOCs mentioned in the report
     * @param threatActor Attribution (e.g., "APT28", "Unknown", "Insider")
     * @param severity Severity level (HIGH, MEDIUM, LOW)
     * @param description Human-readable description of the threat
     */
    public ThreatReport(String reportId, Instant timestamp, List<IOC> iocs,
                       String threatActor, String severity, String description) {
        if (reportId == null || reportId.trim().isEmpty()) {
            throw new IllegalArgumentException("Report ID cannot be null or empty");
        }
        if (timestamp == null) {
            throw new IllegalArgumentException("Timestamp cannot be null");
        }
        if (iocs == null) {
            throw new IllegalArgumentException("IOCs list cannot be null");
        }

        this.reportId = reportId;
        this.timestamp = timestamp;
        this.iocs = new ArrayList<>(iocs); // Defensive copy
        this.threatActor = threatActor != null ? threatActor : "Unknown";
        this.severity = severity != null ? severity : "MEDIUM";
        this.description = description;
    }

    public String getReportId() {
        return reportId;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public List<IOC> getIocs() {
        return Collections.unmodifiableList(iocs);
    }

    public String getThreatActor() {
        return threatActor;
    }

    public String getSeverity() {
        return severity;
    }

    public String getDescription() {
        return description;
    }

    /**
     * Checks if this report contains a specific IOC.
     *
     * @param ioc The IOC to check
     * @return true if the IOC is in this report
     */
    public boolean containsIOC(IOC ioc) {
        return iocs.contains(ioc);
    }

    /**
     * Gets count of IOCs of a specific type in this report.
     *
     * @param type The IOC type to count
     * @return Number of IOCs of that type
     */
    public long countIOCsByType(IOCType type) {
        return iocs.stream().filter(ioc -> ioc.getType() == type).count();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ThreatReport that = (ThreatReport) o;
        return reportId.equals(that.reportId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(reportId);
    }

    @Override
    public String toString() {
        return String.format("ThreatReport{id='%s', timestamp=%s, iocCount=%d, actor='%s', severity='%s'}",
                           reportId, timestamp, iocs.size(), threatActor, severity);
    }
}
