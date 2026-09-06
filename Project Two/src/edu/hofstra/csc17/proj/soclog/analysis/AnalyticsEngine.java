package edu.hofstra.csc17.proj.soclog.analysis;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import edu.hofstra.csc17.proj.soclog.model.entity.FileInfo;
import edu.hofstra.csc17.proj.soclog.model.entity.NetworkInfo;
import edu.hofstra.csc17.proj.soclog.model.entity.ProcessInfo;
import edu.hofstra.csc17.proj.soclog.model.event.Event;
import edu.hofstra.csc17.proj.soclog.model.event.EventType;
import edu.hofstra.csc17.proj.soclog.ioc.IOCMatcher;
import edu.hofstra.csc17.proj.soclog.ioc.ThreatReportParser;
import edu.hofstra.csc17.proj.soclog.ioc.index.InvertedIndex;
import edu.hofstra.csc17.proj.soclog.ioc.model.IOC;
import edu.hofstra.csc17.proj.soclog.ioc.model.IOCType;
import edu.hofstra.csc17.proj.soclog.ioc.model.ThreatReport;

public class AnalyticsEngine {
    private final List<Event> events;

    /**
     * Construct the engine with an initial collection of validated and deduplicated events.
     */
    public AnalyticsEngine(List<Event> events) {
        this.events = new ArrayList<>(Objects.requireNonNull(events));
        // Sort events by timestamp for efficient querying
        this.events.sort(Comparator.comparing(Event::getTimestamp));
    }

    // ========== IOC EXTRACTION & THREAT INTELLIGENCE ==========

    /**
     * Loads threat intelligence reports from a CSV file.
     *
     * @param csvPath Path to the threat reports CSV file
     * @return List of parsed threat reports
     * @throws IOException if file cannot be read
     */
    public static List<ThreatReport> loadThreatReports(Path csvPath) throws IOException {
        return ThreatReportParser.parseThreatReports(csvPath);
    }

    /**
     * Extracts all IOCs from a list of threat reports.
     *
     * @param reports List of threat reports
     * @return List of all IOCs from the reports
     */
    public static List<IOC> extractIOCsFromReports(List<ThreatReport> reports) {
        return ThreatReportParser.extractAllIOCs(reports);
    }

    /**
     * Scans all events for matches against known IOCs.
     *
     * @param knownIOCs List of known IOCs to match against
     * @return Map of events to their matching IOCs
     */
    public Map<Event, List<IOC>> scanForThreats(List<IOC> knownIOCs) {
        IOCMatcher matcher = new IOCMatcher(knownIOCs);
        return matcher.matchEvents(events);
    }

    /**
     * Extracts all unique IOCs (Indicators of Compromise) from the event dataset.
     *
     * Time Complexity: O(e * k) where e = events and k = IOCs extracted per event.
     * Space Complexity: O(u) where u = unique IOCs extracted.
     * Justification: Each event is visited once and extracted IOCs are stored in a HashSet.
     *
     * @return Set of unique IOCs extracted from events
     */
    public Set<IOC> extractAllIOCs() {
        Set<IOC> iocs = new HashSet<>();
        for (Event event : events) {
            iocs.addAll(extractIOCsFromEvent(event));
        }
        return iocs;
    }

    /**
     * Extracts IOCs from events within a specific time window.
     *
     * Time Complexity: O(e * k) where e = events and k = IOCs extracted per matching event.
     * Space Complexity: O(u) where u = unique IOCs extracted from the time window.
     * Justification: Each event is checked against the inclusive window and matching event IOCs are stored in a HashSet.
     *
     * @param startInclusive Start of time window
     * @param endInclusive End of time window
     * @return Set of IOCs extracted from events in the time window
     */
    public Set<IOC> extractIOCs(Instant startInclusive, Instant endInclusive) {
        validateWindow(startInclusive, endInclusive);

        Set<IOC> iocs = new HashSet<>();
        for (Event event : events) {
            if (isInWindow(event, startInclusive, endInclusive)) {
                iocs.addAll(extractIOCsFromEvent(event));
            }
        }
        return iocs;
    }

    /**
     * Finds all events associated with a specific IOC.
     * This helps trace the activity of a known malicious indicator.
     *
     * Time Complexity: O(e * k) where e = events and k = IOCs extracted per event.
     * Space Complexity: O(m) where m = matching events.
     * Justification: Each event is scanned once and matching events are appended to the result list.
     *
     * @param ioc The IOC to search for
     * @return List of events containing the IOC
     */
    public List<Event> findEventsWithIOC(IOC ioc) {
        if (ioc == null) {
            throw new IllegalArgumentException("ioc cannot be null");
        }

        List<Event> matches = new ArrayList<>();
        for (Event event : events) {
            if (extractIOCsFromEvent(event).contains(ioc)) {
                matches.add(event);
            }
        }
        return matches;
    }

    /**
     * Finds the most frequently observed IOCs across all events.
     * Useful for identifying persistent threats.
     *
     * Time Complexity: O(e * k + u^2) where e = events, k = IOCs per event, and u = unique IOCs.
     * Space Complexity: O(u).
     * Justification: IOC counts are built with a HashMap, then unique IOC count entries are insertion-sorted for deterministic ranking.
     *
     * @param limit Number of top IOCs to return
     * @return Map of IOC to occurrence count, sorted by frequency
     */
    public Map<IOC, Long> findTopIOCs(int limit) {
        if (limit <= 0) {
            throw new IllegalArgumentException("limit must be greater than 0");
        }

        Map<IOC, Long> counts = new HashMap<>();
        for (Event event : events) {
            List<IOC> eventIOCs = extractIOCsFromEvent(event);
            for (IOC ioc : eventIOCs) {
                addCount(counts, ioc);
            }
        }

        return rankIOCCounts(counts, limit);
    }

    // ========== INVERTED INDEX OPERATIONS ==========

    /**
     * Builds an inverted index from threat reports for fast IOC lookups.
     *
     * Algorithm:
     * 1. Create new InvertedIndex()
     * 2. For each report in threatReports:
     *    - Call index.indexReport(report)
     * 3. Return the index
     *
     * Time Complexity: O(r * i * l) where r = reports, i = average IOCs per report, and l = average IOC string length.
     * Space Complexity: O(u * l + r) where u = unique indexed IOCs.
     * Justification: Each report is indexed once; exact hash entries and trie paths are created for unique IOC values.
     *
     * @param threatReports List of threat intelligence reports
     * @return InvertedIndex for fast IOC searching
     */
    public InvertedIndex buildThreatIntelligenceIndex(List<ThreatReport> threatReports) {
        if (threatReports == null) {
            throw new IllegalArgumentException("threatReports cannot be null");
        }

        InvertedIndex index = new InvertedIndex();
        for (ThreatReport report : threatReports) {
            index.indexReport(report);
        }
        return index;
    }

    /**
     * Correlates events with threat reports using inverted index.
     * For each event, extracts IOCs and finds matching threat reports.
     *
     * Algorithm:
     * 1. Create result map: Event -> List<ThreatReport>
     * 2. For each event in this.events:
     *    a. Extract IOCs from the event 
     *    b. For each extracted IOC:
     *       - Use index.searchExact(ioc) to find matching threat reports
     *       - Collect all matching reports 
     *    c. If any reports found, add event -> reports to result map
     * 3. Return result map
     *
     * Time Complexity: O(e * k * q + s) where e = events, k = IOCs per event, q = exact lookup cost, and s = sorting matched reports.
     * Space Complexity: O(m + r) where m = matching events and r = total reports stored in result lists.
     * Justification: Each event IOC is looked up in the index and unique matching reports are sorted per matching event.
     *
     * @param index The inverted index of threat reports
     * @return Map of events to the threat reports they match
     */
    public Map<Event, List<ThreatReport>> findThreatsUsingIndex(InvertedIndex index) {
        if (index == null) {
            throw new IllegalArgumentException("index cannot be null");
        }

        Map<Event, List<ThreatReport>> results = new LinkedHashMap<>();
        for (Event event : events) {
            Set<ThreatReport> eventReports = new HashSet<>();
            for (IOC ioc : extractIOCsFromEvent(event)) {
                eventReports.addAll(index.searchExact(ioc));
            }

            if (!eventReports.isEmpty()) {
                results.put(event, sortReports(eventReports));
            }
        }
        return results;
    }

    /**
     * Finds events with IOCs matching a prefix pattern (e.g., "192.168.*", "*.evil.com").
     * Uses inverted index for efficient prefix search.
     *
     * Algorithm:
     * 1. Use index.searchPrefix(prefix, type) to find all matching threat reports
     * 2. Extract all IOCs from matching reports into a Set
     * 3. For each event in this.events:
     *    a. Extract IOCs from event
     *    b. Check if any extracted IOC is in the target IOC set
     *    c. If match found, add event to result list
     * 4. Return list of matching events
     *
     * Time Complexity: O(p + r * i + e * k) where p = prefix length, r = matching reports, i = IOCs per report, and e = events.
     * Space Complexity: O(t + m) where t = target IOCs from prefix reports and m = matching events.
     * Justification: The trie finds reports by prefix, report IOCs are collected into a HashSet, and each event is checked once.
     *
     * @param index The inverted index
     * @param prefix The prefix pattern to search
     * @param type IOC type (DOMAIN or IP_ADDRESS)
     * @return List of events matching the prefix pattern
     */
    public List<Event> findEventsWithPrefixPattern(InvertedIndex index, String prefix, IOCType type) {
        if (index == null) {
            throw new IllegalArgumentException("index cannot be null");
        }

        List<ThreatReport> reports = index.searchPrefix(prefix, type);
        Set<IOC> targetIOCs = new HashSet<>();
        for (ThreatReport report : reports) {
            for (IOC ioc : report.getIocs()) {
                if (ioc.getType() == type) {
                    targetIOCs.add(ioc);
                }
            }
        }

        List<Event> matches = new ArrayList<>();
        for (Event event : events) {
            if (containsAnyIOC(extractIOCsFromEvent(event), targetIOCs)) {
                matches.add(event);
            }
        }
        return matches;
    }

    /**
     * Finds all network events communicating with IPs in a specific subnet.
     * Example: prefix = "192.168.1." finds all IPs in 192.168.1.0/24 subnet
     *
     * Algorithm:
     * 1. Filter this.events to network event types (SendToEvent, ReceiveFromEvent)
     * 2. For each network event:
     *    a. Extract the IP address from NetworkInfo
     *    b. Check if IP address starts with subnetPrefix
     *    c. If match, add event to result list
     * 3. Return list of matching events
     *
     * Time Complexity: O(e * p) where e = events and p = subnet prefix length for network events.
     * Space Complexity: O(m) where m = matching network events.
     * Justification: Each event is checked once, and network IP strings are compared with startsWith.
     *
     * @param subnetPrefix IP prefix (e.g., "192.168.1.", "10.0.")
     * @return List of network events in the subnet
     */
    public List<Event> findEventsInSubnet(String subnetPrefix) {
        if (subnetPrefix == null || subnetPrefix.trim().isEmpty()) {
            throw new IllegalArgumentException("subnetPrefix cannot be null or empty");
        }

        List<Event> matches = new ArrayList<>();
        for (Event event : events) {
            if (isNetworkEvent(event) && event.getObject() instanceof NetworkInfo) {
                NetworkInfo network = (NetworkInfo) event.getObject();
                if (network.getIpAddress().startsWith(subnetPrefix)) {
                    matches.add(event);
                }
            }
        }
        return matches;
    }

    /**
     * Performs bulk IOC lookup across multiple threat reports using inverted index.
     * Much faster than individual lookups: O(n) instead of O(n × m)
     *
     * Algorithm:
     * 1. Validate index and iocs are not null
     * 2. Use index.searchBatch(iocs) to perform bulk lookup
     * 3. This leverages the inverted index for O(n) complexity where n = number of IOCs
     * 4. Return map of IOC -> List<ThreatReport>
     *
     * Time Complexity: O(n + s) average, where n = lookup IOCs and s = total sorting work from exact lookup results.
     * Space Complexity: O(n + r) where r = total matching reports returned.
     * Justification: Delegates to the index batch lookup, which performs one exact lookup per IOC.
     *
     * @param index The inverted index
     * @param iocs List of IOCs to search for
     * @return Map of IOC to list of threat reports containing it
     */
    public Map<IOC, List<ThreatReport>> bulkIOCLookup(InvertedIndex index, List<IOC> iocs) {
        if (index == null) {
            throw new IllegalArgumentException("index cannot be null");
        }
        if (iocs == null) {
            throw new IllegalArgumentException("iocs cannot be null");
        }
        return index.searchBatch(iocs);
    }

    /**
     * Time: O(1) for this event model.
     * Space: O(1), because each event exposes only a few IOC fields.
     * Reason: Checks process, network, and file data once.
     */
    private List<IOC> extractIOCsFromEvent(Event event) {
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
     * Reason: Compares the event type to a fixed set of file event values.
     */
    private boolean isFileEvent(Event event) {
        return event.getType() == EventType.read
                || event.getType() == EventType.write
                || event.getType() == EventType.execute
                || event.getType() == EventType.open
                || event.getType() == EventType.close;
    }

    /**
     * Time: O(1).
     * Space: O(1).
     * Reason: Checks nulls and compares two timestamps.
     */
    private void validateWindow(Instant startInclusive, Instant endInclusive) {
        if (startInclusive == null || endInclusive == null) {
            throw new IllegalArgumentException("startInclusive and endInclusive cannot be null");
        }
        if (startInclusive.isAfter(endInclusive)) {
            throw new IllegalArgumentException("startInclusive cannot be after endInclusive");
        }
    }

    /**
     * Time: O(1).
     * Space: O(1).
     * Reason: Compares one event timestamp with the window bounds.
     */
    private boolean isInWindow(Event event, Instant startInclusive, Instant endInclusive) {
        return !event.getTimestamp().isBefore(startInclusive)
                && !event.getTimestamp().isAfter(endInclusive);
    }

    /**
     * Time: O(1) average.
     * Space: O(1), plus one entry if the key is new.
     * Reason: Updates a HashMap counter.
     */
    private <T> void addCount(Map<T, Long> counts, T key) {
        Long current = counts.get(key);
        if (current == null) {
            counts.put(key, 1L);
        } else {
            counts.put(key, current + 1L);
        }
    }

    /**
     * Time: O(u^2), where u is unique IOC count.
     * Space: O(u).
     * Reason: Copies map entries, insertion-sorts them, then returns up to limit.
     */
    private Map<IOC, Long> rankIOCCounts(Map<IOC, Long> counts, int limit) {
        List<Map.Entry<IOC, Long>> entries = new ArrayList<>(counts.entrySet());
        sortIOCCountEntries(entries);

        Map<IOC, Long> ranked = new LinkedHashMap<>();
        int max = Math.min(limit, entries.size());
        for (int i = 0; i < max; i++) {
            Map.Entry<IOC, Long> entry = entries.get(i);
            ranked.put(entry.getKey(), entry.getValue());
        }
        return ranked;
    }

    /**
     * Time: O(u^2), where u is entry count.
     * Space: O(1).
     * Reason: Uses insertion sort in place.
     */
    private void sortIOCCountEntries(List<Map.Entry<IOC, Long>> entries) {
        for (int i = 1; i < entries.size(); i++) {
            Map.Entry<IOC, Long> current = entries.get(i);
            int j = i - 1;
            while (j >= 0 && compareIOCCountEntries(entries.get(j), current) > 0) {
                entries.set(j + 1, entries.get(j));
                j--;
            }
            entries.set(j + 1, current);
        }
    }

    /**
     * Time: O(l), where l is IOC value length when tie-breaking by value.
     * Space: O(1).
     * Reason: Compares counts, types, then normalized IOC values.
     */
    private int compareIOCCountEntries(Map.Entry<IOC, Long> e1, Map.Entry<IOC, Long> e2) {
        int countComparison = Long.compare(e2.getValue(), e1.getValue());
        if (countComparison != 0) {
            return countComparison;
        }

        IOC ioc1 = e1.getKey();
        IOC ioc2 = e2.getKey();
        int typeComparison = ioc1.getType().name().compareTo(ioc2.getType().name());
        if (typeComparison != 0) {
            return typeComparison;
        }
        return ioc1.getNormalizedValue().compareTo(ioc2.getNormalizedValue());
    }

    /**
     * Time: O(k) average, where k is event IOC count.
     * Space: O(1).
     * Reason: Checks each event IOC against a HashSet.
     */
    private boolean containsAnyIOC(List<IOC> eventIOCs, Set<IOC> targetIOCs) {
        for (IOC ioc : eventIOCs) {
            if (targetIOCs.contains(ioc)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Time: O(r^2), where r is report count.
     * Space: O(r), for the returned list.
     * Reason: Copies reports, then insertion-sorts by report ID.
     */
    private List<ThreatReport> sortReports(Set<ThreatReport> reports) {
        List<ThreatReport> sorted = new ArrayList<>(reports);
        for (int i = 1; i < sorted.size(); i++) {
            ThreatReport current = sorted.get(i);
            int j = i - 1;
            while (j >= 0 && sorted.get(j).getReportId().compareTo(current.getReportId()) > 0) {
                sorted.set(j + 1, sorted.get(j));
                j--;
            }
            sorted.set(j + 1, current);
        }
        return sorted;
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
