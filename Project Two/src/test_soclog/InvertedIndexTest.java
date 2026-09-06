package test_soclog;

import edu.hofstra.csc17.proj.soclog.ioc.index.InvertedIndex;
import edu.hofstra.csc17.proj.soclog.ioc.model.IOC;
import edu.hofstra.csc17.proj.soclog.ioc.model.IOCType;
import edu.hofstra.csc17.proj.soclog.ioc.model.ThreatReport;
import org.junit.Before;
import org.junit.Test;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

public class InvertedIndexTest {

    private InvertedIndex index;
    private IOC domainIOC;
    private IOC subdomainIOC;
    private IOC ipIOC;
    private IOC secondIPIOC;
    private IOC hashIOC;
    private ThreatReport report1;
    private ThreatReport report2;
    private ThreatReport report3;

    @Before
    public void setUp() {
        index = new InvertedIndex();

        domainIOC = new IOC("evil.com", IOCType.DOMAIN);
        subdomainIOC = new IOC("payload.evil.com", IOCType.DOMAIN);
        ipIOC = new IOC("192.168.1.100", IOCType.IP_ADDRESS);
        secondIPIOC = new IOC("192.168.2.25", IOCType.IP_ADDRESS);
        hashIOC = new IOC("abc123", IOCType.FILE_HASH);

        report1 = new ThreatReport(
            "RPT001",
            Instant.parse("2024-01-15T10:00:00Z"),
            Arrays.asList(domainIOC, ipIOC),
            "APT28",
            "HIGH",
            "Test report 1"
        );

        report2 = new ThreatReport(
            "RPT002",
            Instant.parse("2024-01-16T10:00:00Z"),
            Arrays.asList(domainIOC, hashIOC),
            "Unknown",
            "MEDIUM",
            "Test report 2"
        );

        report3 = new ThreatReport(
            "RPT003",
            Instant.parse("2024-01-17T10:00:00Z"),
            Arrays.asList(subdomainIOC, secondIPIOC),
            "APT29",
            "LOW",
            "Test report 3"
        );
    }

    @Test
    public void testSearchExact_Found() {
        index.indexReport(report1);
        index.indexReport(report2);

        List<ThreatReport> results = index.searchExact(domainIOC);
        assertEquals(2, results.size());
        assertTrue(results.contains(report1));
        assertTrue(results.contains(report2));
    }

    @Test
    public void testSearchExact_NotFound() {
        index.indexReport(report1);

        IOC unknownIOC = new IOC("unknown.com", IOCType.DOMAIN);
        List<ThreatReport> results = index.searchExact(unknownIOC);
        assertTrue(results.isEmpty());
    }

    @Test
    public void testSearchExact_CaseInsensitiveDomain() {
        index.indexReport(report1);

        IOC upperCaseDomain = new IOC("EVIL.COM", IOCType.DOMAIN);
        List<ThreatReport> results = index.searchExact(upperCaseDomain);

        assertEquals(1, results.size());
        assertEquals(report1, results.get(0));
    }

    @Test
    public void testSearchPrefix_IPAddress() {
        index.indexReport(report1);
        index.indexReport(report3);

        List<ThreatReport> results = index.searchPrefix("192.168.", IOCType.IP_ADDRESS);

        assertEquals(2, results.size());
        assertTrue(results.contains(report1));
        assertTrue(results.contains(report3));
    }

    @Test
    public void testSearchPrefix_Domain() {
        index.indexReport(report1);
        index.indexReport(report3);

        List<ThreatReport> results = index.searchPrefix("evil", IOCType.DOMAIN);

        assertEquals(1, results.size());
        assertTrue(results.contains(report1));
    }

    @Test
    public void testSearchPrefix_WildcardDomainSuffix() {
        index.indexReport(report1);
        index.indexReport(report3);

        List<ThreatReport> results = index.searchPrefix("*.evil.com", IOCType.DOMAIN);

        assertEquals(1, results.size());
        assertTrue(results.contains(report3));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSearchPrefix_UnsupportedType_ThrowsException() {
        index.searchPrefix("abc", IOCType.FILE_HASH);
    }

    @Test
    public void testCounts_AfterIndexingReports() {
        index.indexReport(report1);
        index.indexReport(report2);

        assertEquals("Should index two reports", 2, index.getReportCount());
        assertEquals("Should count unique IOCs only", 3, index.getUniqueIOCCount());
    }

    @Test
    public void testRemoveReport_RemovesFromAllIndexes() {
        index.indexReport(report1);
        index.indexReport(report2);

        boolean removed = index.removeReport("RPT001");

        assertTrue("Report should be removed", removed);
        assertEquals(1, index.getReportCount());
        assertEquals(2, index.getUniqueIOCCount());
        assertFalse(index.searchExact(domainIOC).contains(report1));
        assertTrue(index.searchExact(ipIOC).isEmpty());
    }

    @Test
    public void testRemoveReport_RemovesFromPrefixIndexes() {
        index.indexReport(report1);
        index.indexReport(report3);

        index.removeReport("RPT001");

        List<ThreatReport> results = index.searchPrefix("192.168.", IOCType.IP_ADDRESS);
        assertEquals(1, results.size());
        assertFalse(results.contains(report1));
        assertTrue(results.contains(report3));
    }

    @Test
    public void testRemoveReport_UnknownReport_ReturnsFalse() {
        index.indexReport(report1);

        assertFalse(index.removeReport("missing"));
        assertEquals(1, index.getReportCount());
    }

    @Test
    public void testSearchBatch_ReturnsResultForEachIOC() {
        index.indexReport(report1);
        index.indexReport(report2);

        IOC unknownIOC = new IOC("unknown.com", IOCType.DOMAIN);
        Map<IOC, List<ThreatReport>> results = index.searchBatch(Arrays.asList(domainIOC, unknownIOC));

        assertEquals(2, results.size());
        assertEquals(2, results.get(domainIOC).size());
        assertTrue(results.get(unknownIOC).isEmpty());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testIndexReport_NullReport_ThrowsException() {
        index.indexReport(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testIndexReport_DuplicateReport_ThrowsException() {
        index.indexReport(report1);
        index.indexReport(report1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSearchExact_NullIOC_ThrowsException() {
        index.searchExact(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRemoveReport_NullReportId_ThrowsException() {
        index.removeReport(null);
    }
}
