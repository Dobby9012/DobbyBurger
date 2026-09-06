package test_soclog;

import edu.hofstra.csc17.proj.soclog.ioc.ThreatReportParser;
import edu.hofstra.csc17.proj.soclog.ioc.model.IOC;
import edu.hofstra.csc17.proj.soclog.ioc.model.IOCType;
import edu.hofstra.csc17.proj.soclog.ioc.model.ThreatReport;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class ThreatReportParserTest {

    @Test
    public void testParseThreatReports_AggregatesRowsByReportId() throws IOException {
        Path tempFile = Files.createTempFile("threat-reports", ".csv");
        Files.write(tempFile, Arrays.asList(
            "report_id,timestamp,ioc_type,ioc_value,severity,threat_actor,description",
            "RPT001,2024-01-15T10:30:00Z,IP_ADDRESS,192.168.1.100,HIGH,APT28,Command and control server",
            "RPT001,2024-01-15T10:30:00Z,FILE_HASH,a1b2c3,HIGH,APT28,Command and control server",
            "RPT002,2024-01-16T14:22:00Z,DOMAIN,malware-cdn.net,MEDIUM,Unknown,Distribution site"
        ));

        List<ThreatReport> reports = ThreatReportParser.parseThreatReports(tempFile);

        assertEquals("Should aggregate rows into two reports", 2, reports.size());

        ThreatReport report1 = findReport(reports, "RPT001");
        assertNotNull("RPT001 should be parsed", report1);
        assertEquals("RPT001 should contain two IOCs", 2, report1.getIocs().size());
        assertTrue(report1.getIocs().contains(new IOC("192.168.1.100", IOCType.IP_ADDRESS)));
        assertTrue(report1.getIocs().contains(new IOC("a1b2c3", IOCType.FILE_HASH)));

        ThreatReport report2 = findReport(reports, "RPT002");
        assertNotNull("RPT002 should be parsed", report2);
        assertTrue(report2.getIocs().contains(new IOC("malware-cdn.net", IOCType.DOMAIN)));

        Files.deleteIfExists(tempFile);
    }

    @Test
    public void testParseThreatReports_SkipsMalformedRows() throws IOException {
        Path tempFile = Files.createTempFile("threat-reports-malformed", ".csv");
        Files.write(tempFile, Arrays.asList(
            "report_id,timestamp,ioc_type,ioc_value,severity,threat_actor,description",
            "bad,row",
            "RPT001,2024-01-15T10:30:00Z,IP_ADDRESS,192.168.1.100,HIGH,APT28,Command and control server"
        ));

        PrintStream originalErr = System.err;
        ByteArrayOutputStream capturedErr = new ByteArrayOutputStream();
        List<ThreatReport> reports;
        try {
            System.setErr(new PrintStream(capturedErr));
            reports = ThreatReportParser.parseThreatReports(tempFile);
        } finally {
            System.setErr(originalErr);
        }

        assertEquals("Should parse valid rows and skip malformed rows", 1, reports.size());
        assertEquals("RPT001", reports.get(0).getReportId());
        assertTrue("Should report malformed row", capturedErr.toString().contains("Skipping malformed line"));

        Files.deleteIfExists(tempFile);
    }

    @Test
    public void testExtractAllIOCs_ReturnsIOCsFromAllReports() {
        IOC ip = new IOC("192.168.1.100", IOCType.IP_ADDRESS);
        IOC domain = new IOC("evil.com", IOCType.DOMAIN);
        ThreatReport report1 = new ThreatReport(
            "RPT001",
            java.time.Instant.parse("2024-01-15T10:00:00Z"),
            Arrays.asList(ip),
            "APT28",
            "HIGH",
            "Test report 1"
        );
        ThreatReport report2 = new ThreatReport(
            "RPT002",
            java.time.Instant.parse("2024-01-16T10:00:00Z"),
            Arrays.asList(domain),
            "Unknown",
            "MEDIUM",
            "Test report 2"
        );

        List<IOC> iocs = ThreatReportParser.extractAllIOCs(Arrays.asList(report1, report2));

        assertEquals(2, iocs.size());
        assertTrue(iocs.contains(ip));
        assertTrue(iocs.contains(domain));
    }

    private ThreatReport findReport(List<ThreatReport> reports, String reportId) {
        for (ThreatReport report : reports) {
            if (report.getReportId().equals(reportId)) {
                return report;
            }
        }
        return null;
    }
}
