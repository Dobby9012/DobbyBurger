package test_soclog;

import edu.hofstra.csc17.proj.soclog.ioc.IOCMatcher;
import edu.hofstra.csc17.proj.soclog.ioc.model.IOC;
import edu.hofstra.csc17.proj.soclog.ioc.model.IOCType;
import edu.hofstra.csc17.proj.soclog.model.entity.FileInfo;
import edu.hofstra.csc17.proj.soclog.model.entity.NetworkInfo;
import edu.hofstra.csc17.proj.soclog.model.entity.ProcessInfo;
import edu.hofstra.csc17.proj.soclog.model.event.Event;
import edu.hofstra.csc17.proj.soclog.model.event.ExecuteEvent;
import edu.hofstra.csc17.proj.soclog.model.event.OpenEvent;
import edu.hofstra.csc17.proj.soclog.model.event.ReadEvent;
import edu.hofstra.csc17.proj.soclog.model.event.ReceiveFromEvent;
import edu.hofstra.csc17.proj.soclog.model.event.SendToEvent;
import org.junit.Before;
import org.junit.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Test suite for IOCMatcher.
 * Students should add more tests to cover edge cases and different IOC types.
 */
public class IOCMatcherTest {

    private IOCMatcher matcher;
    private List<IOC> knownIOCs;

    private IOC maliciousIP;
    private IOC maliciousProcess;
    private IOC maliciousFile;

    private ProcessInfo normalProcess;
    private ProcessInfo maliciousProcessInfo;
    private NetworkInfo maliciousNetworkInfo;
    private FileInfo maliciousFileInfo;
    private FileInfo normalFileInfo;

    @Before
    public void setUp() {
        // Initialize test IOCs
        maliciousIP = new IOC("192.168.1.100", IOCType.IP_ADDRESS);
        maliciousProcess = new IOC("malware.exe", IOCType.PROCESS_NAME);
        maliciousFile = new IOC("/tmp/backdoor.sh", IOCType.FILE_PATH);

        knownIOCs = Arrays.asList(maliciousIP, maliciousProcess, maliciousFile);
        matcher = new IOCMatcher(knownIOCs);

        // Initialize test entities
        normalProcess = new ProcessInfo("chrome", 1234, "/usr/bin/chrome", "user");
        maliciousProcessInfo = new ProcessInfo("malware.exe", 6666, "/tmp/malware.exe", "root");
        maliciousNetworkInfo = new NetworkInfo("192.168.1.100", 443, "TCP");
        maliciousFileInfo = new FileInfo("/tmp/backdoor.sh", 10, "755");
        normalFileInfo = new FileInfo("/etc/passwd", 5, "644");
    }

    @Test
    public void testMatchEvent_ProcessName_Match() {
        Event event = new ExecuteEvent(
            Instant.now(),
            maliciousProcessInfo,
            normalFileInfo,
            "0"
        );

        List<IOC> matches = matcher.matchEvent(event);
        assertFalse("Should find matches for malicious process", matches.isEmpty());

        boolean foundProcessIOC = false;
        for (IOC ioc : matches) {
            if (ioc.getType() == IOCType.PROCESS_NAME) {
                foundProcessIOC = true;
                break;
            }
        }
        assertTrue("Should contain process name IOC", foundProcessIOC);
    }

    @Test
    public void testMatchEvent_ProcessName_CaseInsensitive() {
        IOC upperCaseProcess = new IOC("MALWARE.EXE", IOCType.PROCESS_NAME);
        IOCMatcher caseMatcher = new IOCMatcher(Arrays.asList(upperCaseProcess));

        Event event = new ExecuteEvent(
            Instant.now(),
            maliciousProcessInfo,
            normalFileInfo,
            "0"
        );

        List<IOC> matches = caseMatcher.matchEvent(event);
        assertEquals("Should match normalized process name", 1, matches.size());
        assertEquals(IOCType.PROCESS_NAME, matches.get(0).getType());
    }

    @Test
    public void testMatchEvent_NetworkIP_Match() {
        Event event = new ReceiveFromEvent(
            Instant.now(),
            normalProcess,
            maliciousNetworkInfo,
            "0"
        );

        List<IOC> matches = matcher.matchEvent(event);
        assertTrue("Should contain malicious IP IOC", matches.contains(maliciousIP));
    }

    @Test
    public void testMatchEvent_FilePath_Match() {
        Event event = new ReadEvent(
            Instant.now(),
            normalProcess,
            maliciousFileInfo,
            "0"
        );

        List<IOC> matches = matcher.matchEvent(event);
        assertTrue("Should contain malicious file path IOC", matches.contains(maliciousFile));
    }

    @Test
    public void testMatchEvent_NoMatch_ReturnsEmptyList() {
        Event event = new OpenEvent(
            Instant.now(),
            normalProcess,
            normalFileInfo,
            "0"
        );

        List<IOC> matches = matcher.matchEvent(event);
        assertTrue("Clean event should not match known IOCs", matches.isEmpty());
    }

    @Test
    public void testMatchEvent_MultipleMatches() {
        Event event = new ExecuteEvent(
            Instant.now(),
            maliciousProcessInfo,
            maliciousFileInfo,
            "0"
        );

        List<IOC> matches = matcher.matchEvent(event);
        assertEquals("Should match process name and file path", 2, matches.size());
        assertTrue(matches.contains(maliciousProcess));
        assertTrue(matches.contains(maliciousFile));
    }

    @Test
    public void testMatchEvents_ReturnsOnlyEventsWithMatches() {
        Event threat = new SendToEvent(
            Instant.now(),
            normalProcess,
            maliciousNetworkInfo,
            "0"
        );

        Event clean = new OpenEvent(
            Instant.now(),
            normalProcess,
            normalFileInfo,
            "0"
        );

        Map<Event, List<IOC>> matches = matcher.matchEvents(Arrays.asList(threat, clean));
        assertEquals("Only one event should match", 1, matches.size());
        assertTrue(matches.containsKey(threat));
        assertFalse(matches.containsKey(clean));
    }

    @Test
    public void testFindThreats_Mixed() {
        Event threat = new SendToEvent(
            Instant.now(),
            normalProcess,
            maliciousNetworkInfo,
            "0"
        );

        Event clean = new OpenEvent(
            Instant.now(),
            normalProcess,
            normalFileInfo,
            "0"
        );

        List<Event> events = Arrays.asList(threat, clean);
        List<Event> threats = matcher.findThreats(events);

        assertEquals("Should find 1 threat", 1, threats.size());
        assertEquals("Should return the malicious event", threat, threats.get(0));
    }

    @Test
    public void testConstructor_EmptyList_AllowsNoMatches() {
        IOCMatcher emptyMatcher = new IOCMatcher(new ArrayList<IOC>());
        Event event = new SendToEvent(
            Instant.now(),
            normalProcess,
            maliciousNetworkInfo,
            "0"
        );

        assertTrue(emptyMatcher.matchEvent(event).isEmpty());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructor_NullList_ThrowsException() {
        new IOCMatcher(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testMatchEvent_NullEvent_ThrowsException() {
        matcher.matchEvent(null);
    }
}
