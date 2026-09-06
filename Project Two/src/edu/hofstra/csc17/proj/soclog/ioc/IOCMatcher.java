package edu.hofstra.csc17.proj.soclog.ioc;

import edu.hofstra.csc17.proj.soclog.ioc.model.IOC;
import edu.hofstra.csc17.proj.soclog.ioc.model.IOCType;
import edu.hofstra.csc17.proj.soclog.model.entity.FileInfo;
import edu.hofstra.csc17.proj.soclog.model.entity.NetworkInfo;
import edu.hofstra.csc17.proj.soclog.model.entity.ProcessInfo;
import edu.hofstra.csc17.proj.soclog.model.event.Event;
import edu.hofstra.csc17.proj.soclog.model.event.EventType;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Comprehensive IOC detection and extraction engine.
 *
 * Use case: Match events against known IOCs from threat intelligence reports
 *
 * Workflow:
 * 1. Load IOCs from threat reports (ThreatReportParser)
 * 2. Create IOCMatcher with known IOCs
 * 3. Match live events against IOCs for threat detection
 */
public class IOCMatcher {
    private final Map<IOCType, Map<String, List<IOC>>> iocsByTypeAndValue;

    /**
     * Time Complexity: O(n) where n = number of known IOCs.
     * Space Complexity: O(n) for the lookup index.
     * Justification: Each IOC is inserted once into hash maps keyed by type and normalized value.
     */
    public IOCMatcher(List<IOC> knownIOCs) {
        if (knownIOCs == null) {
            throw new IllegalArgumentException("knownIOCs cannot be null");
        }

        this.iocsByTypeAndValue = new HashMap<>();
        for (IOC ioc : knownIOCs) {
            if (ioc != null) {
                addToIndex(ioc);
            }
        }
    }

    /**
     * Matches a single event against known IOCs.
     * 
     * Algorithm:
     * 1. Extract relevant fields from the event (e.g., source IP, user agent)
     * 2. Compare extracted fields against known IOCs
     * 3. Return a list of matching IOCs
     *
     * Time Complexity: O(k + m) where k = extracted IOCs from the event and m = matched IOCs.
     * Space Complexity: O(k + m) for extracted IOCs and duplicate tracking.
     * Justification: Event extraction is constant for this event model, then hash lookups find matches by type/value.
     *
     * @param event The event to check
     * @return List of matched IOCs (type, value, source context)
     */
    public List<IOC> matchEvent(Event event) {
        if (event == null) {
            throw new IllegalArgumentException("event cannot be null");
        }

        List<IOC> extracted = extractIOCs(event);
        List<IOC> matches = new ArrayList<>();
        Set<IOC> seen = new HashSet<>();

        for (IOC candidate : extracted) {
            Map<String, List<IOC>> values = iocsByTypeAndValue.get(candidate.getType());
            if (values == null) {
                continue;
            }

            List<IOC> knownMatches = values.get(candidate.getNormalizedValue());
            if (knownMatches == null) {
                continue;
            }

            for (IOC match : knownMatches) {
                if (seen.add(match)) {
                    matches.add(match);
                }
            }
        }

        return matches;
    }

    /**
     * Matches multiple events against known IOCs.
     *
     * Time Complexity: O(e * (k + m)) where e = events, k = extracted IOCs per event, and m = matches per event.
     * Space Complexity: O(t + r) where t = threat events and r = total matched IOCs stored in the result.
     * Justification: Each event is matched independently and only matching events are stored.
     *
     * @param events List of events to check
     * @return Map of events to their matched IOCs
     */
    public Map<Event, List<IOC>> matchEvents(List<Event> events) {
        Map<Event, List<IOC>> results = new HashMap<>();

        for (Event event : events) {
            List<IOC> matches = matchEvent(event);
            if (!matches.isEmpty()) {
                results.put(event, matches);
            }
        }

        return results;
    }

    /**
     * Finds all events that match any known IOC.
     *
     * Time Complexity: O(e * (k + m)) where e = events, k = extracted IOCs per event, and m = matches per event.
     * Space Complexity: O(t) where t = events that match at least one IOC.
     * Justification: Each event is checked once, and only threat events are added to the result list.
     *
     * @param events List of events to check
     * @return List of events that contain known IOCs
     */
    public List<Event> findThreats(List<Event> events) {
        List<Event> threats = new ArrayList<>();

        for (Event event : events) {
            if (!matchEvent(event).isEmpty()) {
                threats.add(event);
            }
        }

        return threats;
    }

    /**
     * Time: O(1) average.
     * Space: O(1), plus one stored IOC reference.
     * Reason: Uses hash maps keyed by IOC type and normalized value.
     */
    private void addToIndex(IOC ioc) {
        Map<String, List<IOC>> values = iocsByTypeAndValue.get(ioc.getType());
        if (values == null) {
            values = new HashMap<>();
            iocsByTypeAndValue.put(ioc.getType(), values);
        }

        String normalized = ioc.getNormalizedValue();
        List<IOC> bucket = values.get(normalized);
        if (bucket == null) {
            bucket = new ArrayList<>();
            values.put(normalized, bucket);
        }
        bucket.add(ioc);
    }

    /**
     * Time: O(1) for this event model.
     * Space: O(1), because each event has only a few IOC fields.
     * Reason: Checks subject, network object, and file object once.
     */
    private List<IOC> extractIOCs(Event event) {
        List<IOC> iocs = new ArrayList<>();

        ProcessInfo subject = event.getSubject();
        if (subject != null && hasText(subject.getName())) {
            iocs.add(new IOC(subject.getName(), IOCType.PROCESS_NAME, "process"));
        }

        if (isNetworkEvent(event) && event.getObject() instanceof NetworkInfo) {
            NetworkInfo network = (NetworkInfo) event.getObject();
            if (hasText(network.getIpAddress())) {
                iocs.add(new IOC(network.getIpAddress(), IOCType.IP_ADDRESS, "network"));
            }
        }

        if (isFileEvent(event) && event.getObject() instanceof FileInfo) {
            FileInfo file = (FileInfo) event.getObject();
            if (hasText(file.getPath())) {
                iocs.add(new IOC(file.getPath(), IOCType.FILE_PATH, "file"));
            }
        }

        return iocs;
    }

    /**
     * Time: O(1).
     * Space: O(1).
     * Reason: Compares the event type to two enum values.
     */
    private boolean isNetworkEvent(Event event) {
        return event.getType() == EventType.sendto || event.getType() == EventType.receivefrom;
    }

    /**
     * Time: O(1).
     * Space: O(1).
     * Reason: Compares the event type to a fixed set of enum values.
     */
    private boolean isFileEvent(Event event) {
        return event.getType() == EventType.read
                || event.getType() == EventType.write
                || event.getType() == EventType.execute
                || event.getType() == EventType.open
                || event.getType() == EventType.close;
    }

    /**
     * Time: O(s), where s is string length.
     * Space: O(1).
     * Reason: trim checks the string before testing emptiness.
     */
    private boolean hasText(String value) {
        return value != null && !value.trim().isEmpty();
    }

}
