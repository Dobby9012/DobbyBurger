package test_soclog.analysis;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

import edu.hofstra.csc17.proj.soclog.analysis.AnalyticsEngine;
import edu.hofstra.csc17.proj.soclog.ioc.index.InvertedIndex;
import edu.hofstra.csc17.proj.soclog.ioc.model.IOC;
import edu.hofstra.csc17.proj.soclog.ioc.model.IOCType;
import edu.hofstra.csc17.proj.soclog.ioc.model.ThreatReport;
import edu.hofstra.csc17.proj.soclog.model.entity.FileInfo;
import edu.hofstra.csc17.proj.soclog.model.entity.NetworkInfo;
import edu.hofstra.csc17.proj.soclog.model.entity.ProcessInfo;
import edu.hofstra.csc17.proj.soclog.model.event.Event;
import edu.hofstra.csc17.proj.soclog.model.event.ExecuteEvent;
import edu.hofstra.csc17.proj.soclog.model.event.OpenEvent;
import edu.hofstra.csc17.proj.soclog.model.event.SendToEvent;
import edu.hofstra.csc17.proj.soclog.model.event.ReceiveFromEvent;

public class AnalyticsEngineTest {

    private AnalyticsEngine analyticsEngine;
    private List<Event> sampleEvents;

    // Test data
    private Instant baseTime;
    private ProcessInfo normalProcess;
    private ProcessInfo maliciousProcess;
    private NetworkInfo normalNetwork;
    private NetworkInfo maliciousNetwork;
    private FileInfo normalFile;
    private FileInfo maliciousFile;

    // Test events
    private Event networkEvent1;
    private Event networkEvent2;
    private Event fileEvent1;
    private Event processEvent1;

    // Threat intelligence data
    private IOC maliciousIP;
    private IOC normalIP;
    private IOC maliciousFilePath;
    private IOC normalProcessName;
    private IOC maliciousDomain;
    private IOC maliciousProcessName;
    private ThreatReport threatReport1;
    private ThreatReport threatReport2;
    private ThreatReport threatReport3;

    @Before
    public void setUp() {
        // Initialize base timestamp
        baseTime = Instant.parse("2024-01-15T10:00:00Z");

        // Create test entities
        normalProcess = new ProcessInfo("chrome", 1234, "/usr/bin/chrome", "user");
        maliciousProcess = new ProcessInfo("malware.exe", 6666, "/tmp/malware.exe", "root");

        normalNetwork = new NetworkInfo("8.8.8.8", 53, "UDP");
        maliciousNetwork = new NetworkInfo("192.168.1.100", 443, "TCP");

        normalFile = new FileInfo("/etc/passwd", 5, "644");
        maliciousFile = new FileInfo("/tmp/backdoor.sh", 10, "755");

        // Create test events with different timestamps
        networkEvent1 = new SendToEvent(
            baseTime,
            normalProcess,
            maliciousNetwork,
            "0"
        );

        networkEvent2 = new ReceiveFromEvent(
            baseTime.plusSeconds(60),
            normalProcess,
            normalNetwork,
            "0"
        );

        fileEvent1 = new OpenEvent(
            baseTime.plusSeconds(120),
            normalProcess,
            maliciousFile,
            "0"
        );

        processEvent1 = new ExecuteEvent(
            baseTime.plusSeconds(180),
            maliciousProcess,
            normalFile,
            "0"
        );

        // Create sample event list
        sampleEvents = Arrays.asList(networkEvent1, networkEvent2, fileEvent1, processEvent1);
        analyticsEngine = new AnalyticsEngine(sampleEvents);

        // Initialize threat intelligence data
        maliciousIP = new IOC("192.168.1.100", IOCType.IP_ADDRESS);
        normalIP = new IOC("8.8.8.8", IOCType.IP_ADDRESS);
        maliciousFilePath = new IOC("/tmp/backdoor.sh", IOCType.FILE_PATH);
        normalProcessName = new IOC("chrome", IOCType.PROCESS_NAME);
        maliciousDomain = new IOC("evil.com", IOCType.DOMAIN);
        maliciousProcessName = new IOC("malware.exe", IOCType.PROCESS_NAME);

        threatReport1 = new ThreatReport(
            "RPT-001",
            Instant.parse("2024-01-10T00:00:00Z"),
            Arrays.asList(maliciousIP, maliciousDomain),
            "APT28",
            "HIGH",
            "Credential harvesting campaign"
        );

        threatReport2 = new ThreatReport(
            "RPT-002",
            Instant.parse("2024-01-12T00:00:00Z"),
            Arrays.asList(maliciousProcessName),
            "Lazarus",
            "CRITICAL",
            "Ransomware deployment"
        );

        threatReport3 = new ThreatReport(
            "RPT-003",
            Instant.parse("2024-01-13T00:00:00Z"),
            Arrays.asList(maliciousFilePath),
            "Unknown",
            "MEDIUM",
            "Backdoor file path"
        );
    }

    @Test
    public void testExtractAllIOCs() {
        Set<IOC> iocs = analyticsEngine.extractAllIOCs();
        assertNotNull("IOC set should not be null", iocs);
        assertFalse("Should extract IOCs from events", iocs.isEmpty());
        assertTrue("Should include malicious network IP", iocs.contains(maliciousIP));
        assertTrue("Should include normal network IP", iocs.contains(normalIP));
        assertTrue("Should include malicious file path", iocs.contains(maliciousFilePath));
        assertTrue("Should include process names", iocs.contains(normalProcessName));
        assertTrue("Should include malicious process name", iocs.contains(maliciousProcessName));
    }

    @Test
    public void testExtractIOCs_TimeWindow() {
        Instant start = baseTime;
        Instant end = baseTime.plusSeconds(90);

        Set<IOC> iocs = analyticsEngine.extractIOCs(start, end);
        assertNotNull("IOC set should not be null", iocs);
        assertTrue("Should include first network event IP", iocs.contains(maliciousIP));
        assertTrue("Should include second network event IP", iocs.contains(normalIP));
        assertFalse("Should not include later file IOC", iocs.contains(maliciousFilePath));
        assertFalse("Should not include later process IOC", iocs.contains(maliciousProcessName));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testExtractIOCs_InvalidTimeWindow_ThrowsException() {
        analyticsEngine.extractIOCs(baseTime.plusSeconds(10), baseTime);
    }

    @Test
    public void testFindEventsWithIOC_IPAddress() {
        List<Event> matches = analyticsEngine.findEventsWithIOC(maliciousIP);

        assertEquals("Should find one event with malicious IP", 1, matches.size());
        assertEquals(networkEvent1, matches.get(0));
    }

    @Test
    public void testFindEventsWithIOC_ProcessName() {
        List<Event> matches = analyticsEngine.findEventsWithIOC(normalProcessName);

        assertEquals("Chrome process appears in three events", 3, matches.size());
        assertTrue(matches.contains(networkEvent1));
        assertTrue(matches.contains(networkEvent2));
        assertTrue(matches.contains(fileEvent1));
    }

    @Test
    public void testFindEventsWithIOC_NotFound() {
        IOC unknown = new IOC("10.10.10.10", IOCType.IP_ADDRESS);

        assertTrue(analyticsEngine.findEventsWithIOC(unknown).isEmpty());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFindEventsWithIOC_NullIOC_ThrowsException() {
        analyticsEngine.findEventsWithIOC(null);
    }

    @Test
    public void testFindTopIOCs() {
        Map<IOC, Long> topIOCs = analyticsEngine.findTopIOCs(2);

        assertEquals("Should return requested limit", 2, topIOCs.size());
        assertEquals("Chrome process should be observed three times",
            Long.valueOf(3L),
            topIOCs.get(normalProcessName));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFindTopIOCs_InvalidLimit_ThrowsException() {
        analyticsEngine.findTopIOCs(0);
    }

    @Test
    public void testBuildThreatIntelligenceIndex() {
        List<ThreatReport> reports = Arrays.asList(threatReport1, threatReport2, threatReport3);
        InvertedIndex index = analyticsEngine.buildThreatIntelligenceIndex(reports);

        assertNotNull("Index should not be null", index);
        assertEquals("Should index 3 reports", 3, index.getReportCount());
        assertEquals("Should make exact IOC lookup available", 1, index.searchExact(maliciousIP).size());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testBuildThreatIntelligenceIndex_NullReports_ThrowsException() {
        analyticsEngine.buildThreatIntelligenceIndex(null);
    }

    @Test
    public void testFindThreatsUsingIndex() {
        InvertedIndex index = analyticsEngine.buildThreatIntelligenceIndex(
            Arrays.asList(threatReport1, threatReport2, threatReport3)
        );

        Map<Event, List<ThreatReport>> matches = analyticsEngine.findThreatsUsingIndex(index);

        assertEquals("Should find three events with known threat IOCs", 3, matches.size());
        assertTrue(matches.get(networkEvent1).contains(threatReport1));
        assertTrue(matches.get(fileEvent1).contains(threatReport3));
        assertTrue(matches.get(processEvent1).contains(threatReport2));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFindThreatsUsingIndex_NullIndex_ThrowsException() {
        analyticsEngine.findThreatsUsingIndex(null);
    }

    @Test
    public void testFindEventsWithPrefixPattern() {
        InvertedIndex index = analyticsEngine.buildThreatIntelligenceIndex(
            Arrays.asList(threatReport1, threatReport2)
        );

        List<Event> matches = analyticsEngine.findEventsWithPrefixPattern(
            index,
            "192.168.",
            IOCType.IP_ADDRESS
        );

        assertEquals("Should find event matching IP prefix from index", 1, matches.size());
        assertEquals(networkEvent1, matches.get(0));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFindEventsWithPrefixPattern_NullIndex_ThrowsException() {
        analyticsEngine.findEventsWithPrefixPattern(null, "192.", IOCType.IP_ADDRESS);
    }

    @Test
    public void testFindEventsInSubnet() {
        String subnet = "192.168.1.";
        List<Event> subnetEvents = analyticsEngine.findEventsInSubnet(subnet);

        assertNotNull("Result should not be null", subnetEvents);
        assertEquals("Should find networkEvent1 which communicates with 192.168.1.100", 1, subnetEvents.size());
        assertEquals(networkEvent1, subnetEvents.get(0));
    }

    @Test
    public void testFindEventsInSubnet_NoMatches() {
        List<Event> subnetEvents = analyticsEngine.findEventsInSubnet("10.0.");

        assertTrue(subnetEvents.isEmpty());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFindEventsInSubnet_NullPrefix_ThrowsException() {
        analyticsEngine.findEventsInSubnet(null);
    }

    @Test
    public void testBulkIOCLookup() {
        InvertedIndex index = analyticsEngine.buildThreatIntelligenceIndex(
            Arrays.asList(threatReport1, threatReport2)
        );

        Map<IOC, List<ThreatReport>> results = analyticsEngine.bulkIOCLookup(
            index,
            Arrays.asList(maliciousIP, maliciousProcessName)
        );

        assertEquals(2, results.size());
        assertEquals(1, results.get(maliciousIP).size());
        assertEquals(1, results.get(maliciousProcessName).size());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testBulkIOCLookup_NullIndex_ThrowsException() {
        analyticsEngine.bulkIOCLookup(null, Arrays.asList(maliciousIP));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testBulkIOCLookup_NullIOCs_ThrowsException() {
        InvertedIndex index = analyticsEngine.buildThreatIntelligenceIndex(Arrays.asList(threatReport1));
        analyticsEngine.bulkIOCLookup(index, null);
    }

    @Test
    public void testEmptyDataset_ReturnsEmptyResults() {
        AnalyticsEngine emptyEngine = new AnalyticsEngine(Arrays.asList());

        assertTrue(emptyEngine.extractAllIOCs().isEmpty());
        assertTrue(emptyEngine.findTopIOCs(3).isEmpty());
        assertTrue(emptyEngine.findEventsInSubnet("192.168.").isEmpty());
    }
}
