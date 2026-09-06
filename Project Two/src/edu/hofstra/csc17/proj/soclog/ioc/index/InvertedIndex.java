package edu.hofstra.csc17.proj.soclog.ioc.index;

import edu.hofstra.csc17.proj.soclog.ioc.model.IOC;
import edu.hofstra.csc17.proj.soclog.ioc.model.IOCType;
import edu.hofstra.csc17.proj.soclog.ioc.model.ThreatReport;

import java.util.*;

/**
 * Inverted index for fast IOC lookups across threat reports.
 *
 * This data structure enables SOC analysts to quickly:
 * - Find all reports containing a specific IOC
 * - Search for IOCs matching a prefix (e.g., "192.168.*", "*.evil.com")
 * - Perform bulk lookups across multiple IOCs
 *
 * Uses hash indexes and tries to support:
 * 1. Fast exact IOC lookups
 * 2. Efficient prefix searching for domains and IP addresses
 * 3. Report storage and retrieval
 */
public class InvertedIndex {

    private final Map<String, ThreatReport> reportsById;
    private final Map<IOC, Set<ThreatReport>> exactIndex;
    private final TrieNode ipPrefixRoot;
    private final TrieNode domainPrefixRoot;
    private final TrieNode reversedDomainRoot;

    /**
     * Creates a new empty inverted index.
     *
     * Time Complexity: O(1).
     * Space Complexity: O(1).
     * Justification: The constructor initializes empty hash maps and trie roots.
     */
    public InvertedIndex() {
        this.reportsById = new HashMap<>();
        this.exactIndex = new HashMap<>();
        this.ipPrefixRoot = new TrieNode();
        this.domainPrefixRoot = new TrieNode();
        this.reversedDomainRoot = new TrieNode();
    }

    /**
     * Indexes a threat report by all its IOCs.
     *
     * Time Complexity: O(i * l) where i = IOCs in the report and l = average IOC string length.
     * Space Complexity: O(i * l) in the worst case for new hash entries and trie nodes.
     * Justification: Each IOC is added to the exact hash index; IP/domain IOCs are also inserted character-by-character into tries.
     *
     * @param report The threat report to index
     * @throws IllegalArgumentException if report is null or already indexed
     */
    public void indexReport(ThreatReport report) {
        if (report == null) {
            throw new IllegalArgumentException("report cannot be null");
        }
        if (reportsById.containsKey(report.getReportId())) {
            throw new IllegalArgumentException("Report already indexed: " + report.getReportId());
        }

        reportsById.put(report.getReportId(), report);
        for (IOC ioc : report.getIocs()) {
            addIOCReport(ioc, report);
        }
    }


    /**
     * Searches for reports containing an exact IOC match.
     *
     * Time Complexity: O(1 + r^2) average, where r = matching reports.
     * Space Complexity: O(r).
     * Justification: Hash lookup is average O(1); the result list is sorted with insertion sort for deterministic output.
     *
     * @param ioc The IOC to search for
     * @return List of matching threat reports (empty list if not found)
     */
    public List<ThreatReport> searchExact(IOC ioc) {
        if (ioc == null) {
            throw new IllegalArgumentException("ioc cannot be null");
        }

        Set<ThreatReport> reports = exactIndex.get(ioc);
        if (reports == null) {
            return new ArrayList<>();
        }
        return sortedReports(reports);
    }

    /**
     * Searches for reports containing IOCs matching a prefix pattern.
     * Only works for domains and IP addresses.
     *
     * Examples:
     * - searchPrefix("192.168.", IP_ADDRESS) finds "192.168.1.1", "192.168.2.100", etc.
     * - searchPrefix("evil", DOMAIN) finds "evil.com", "evil.org", "evilcorp.net", etc.
     * - searchPrefix("*.evil.com", DOMAIN) matches domains ending with ".evil.com"
     *
     * Time Complexity: O(p + r^2) where p = prefix length and r = matching reports.
     * Space Complexity: O(r).
     * Justification: Trie traversal follows one character per prefix character; matching reports are copied and sorted.
     *
     * @param prefix The prefix pattern to search for
     * @param type The IOC type (must be DOMAIN or IP_ADDRESS)
     * @return List of matching threat reports (empty list if not found)
     * @throws IllegalArgumentException if type is not DOMAIN or IP_ADDRESS
     */
    public List<ThreatReport> searchPrefix(String prefix, IOCType type) {
        if (prefix == null) {
            throw new IllegalArgumentException("prefix cannot be null");
        }
        if (type != IOCType.DOMAIN && type != IOCType.IP_ADDRESS) {
            throw new IllegalArgumentException("Prefix search only supports DOMAIN and IP_ADDRESS");
        }

        String normalizedPrefix = prefix.trim().toLowerCase();
        if (type == IOCType.IP_ADDRESS) {
            return sortedReports(searchTrie(ipPrefixRoot, normalizedPrefix));
        }
        if (normalizedPrefix.startsWith("*.")) {
            return sortedReports(searchTrie(reversedDomainRoot, reverse(normalizedPrefix.substring(1))));
        }
        return sortedReports(searchTrie(domainPrefixRoot, normalizedPrefix));
    }


    /**
     * Searches for reports containing any of the given IOCs (bulk search).
     *
     * Time Complexity: O(n + s) average, where n = lookup IOCs and s = total sorting work across result lists.
     * Space Complexity: O(n + r) where r = total matching reports returned.
     * Justification: Each IOC uses exact hash lookup, then each result list is copied and sorted.
     *
     * @param iocs List of IOCs to search for
     * @return Map of IOC to list of matching reports
     */
    public Map<IOC, List<ThreatReport>> searchBatch(List<IOC> iocs) {
        if (iocs == null) {
            throw new IllegalArgumentException("IOCs list cannot be null");
        }

        Map<IOC, List<ThreatReport>> results = new HashMap<>();
        for (IOC ioc : iocs) {
            results.put(ioc, searchExact(ioc));
        }
        return results;
    }

    /**
     * Removes a report from the index.
     * Note: This is an expensive operation as it may require cleanup across data structures.
     *
     * Time Complexity: O(i * l) where i = IOCs in the removed report and l = average IOC string length.
     * Space Complexity: O(1) beyond existing index storage.
     * Justification: Each IOC is removed from the exact index; IP/domain trie report sets are updated along each string path.
     *
     * @param reportId The report ID to remove
     * @return true if the report was removed, false otherwise
     */
    public boolean removeReport(String reportId) {
        if (reportId == null || reportId.trim().isEmpty()) {
            throw new IllegalArgumentException("reportId cannot be null or empty");
        }

        ThreatReport removed = reportsById.remove(reportId);
        if (removed == null) {
            return false;
        }

        for (IOC ioc : removed.getIocs()) {
            Set<ThreatReport> reports = exactIndex.get(ioc);
            if (reports != null) {
                reports.remove(removed);
                if (reports.isEmpty()) {
                    exactIndex.remove(ioc);
                }
            }
            removeFromPrefixIndexes(ioc, removed);
        }

        return true;
    }

    /**
     * Gets the total number of indexed reports.
     *
     * Time Complexity: O(1).
     * Space Complexity: O(1).
     * Justification: The report count is the size of the report ID hash map.
     *
     * @return Number of indexed threat reports
     */
    public int getReportCount() {
        return reportsById.size();
    }

    /**
     * Gets the total number of unique IOCs indexed.
     *
     * Time Complexity: O(1).
     * Space Complexity: O(1).
     * Justification: The unique IOC count is the size of the exact IOC hash map.
     *
     * @return Number of unique IOCs
     */
    public int getUniqueIOCCount() {
        return exactIndex.size();
    }

    /**
     * Time: O(l), where l is IOC length for trie-backed types.
     * Space: O(l), for possible new trie nodes.
     * Reason: Adds to the exact hash index and then to prefix indexes when needed.
     */
    private void addIOCReport(IOC ioc, ThreatReport report) {
        if (ioc == null) {
            return;
        }

        Set<ThreatReport> reports = exactIndex.get(ioc);
        if (reports == null) {
            reports = new HashSet<>();
            exactIndex.put(ioc, reports);
        }
        reports.add(report);
        addToPrefixIndexes(ioc, report);
    }

    /**
     * Time: O(l), or O(2l) for domains because the reversed trie is also updated.
     * Space: O(l), for possible new trie nodes.
     * Reason: IPs use one trie; domains use forward and reversed tries.
     */
    private void addToPrefixIndexes(IOC ioc, ThreatReport report) {
        if (ioc.getType() == IOCType.IP_ADDRESS) {
            insertTrie(ipPrefixRoot, ioc.getNormalizedValue(), report);
        } else if (ioc.getType() == IOCType.DOMAIN) {
            insertTrie(domainPrefixRoot, ioc.getNormalizedValue(), report);
            insertTrie(reversedDomainRoot, reverse(ioc.getNormalizedValue()), report);
        }
    }

    /**
     * Time: O(l), or O(2l) for domains.
     * Space: O(1).
     * Reason: Walks the same trie paths used during insertion and removes the report reference.
     */
    private void removeFromPrefixIndexes(IOC ioc, ThreatReport report) {
        if (ioc.getType() == IOCType.IP_ADDRESS) {
            removeTrieReport(ipPrefixRoot, ioc.getNormalizedValue(), report);
        } else if (ioc.getType() == IOCType.DOMAIN) {
            removeTrieReport(domainPrefixRoot, ioc.getNormalizedValue(), report);
            removeTrieReport(reversedDomainRoot, reverse(ioc.getNormalizedValue()), report);
        }
    }

    /**
     * Time: O(l), where l is value length.
     * Space: O(l), if all nodes on the path are new.
     * Reason: Inserts one character at a time into the trie.
     */
    private void insertTrie(TrieNode root, String value, ThreatReport report) {
        TrieNode current = root;
        current.reports.add(report);
        for (int i = 0; i < value.length(); i++) {
            Character character = Character.valueOf(value.charAt(i));
            TrieNode next = current.children.get(character);
            if (next == null) {
                next = new TrieNode();
                current.children.put(character, next);
            }
            current = next;
            current.reports.add(report);
        }
    }

    /**
     * Time: O(p + r), where p is prefix length and r is reports at the prefix node.
     * Space: O(r).
     * Reason: Walks the prefix path, then copies the node's report set.
     */
    private Set<ThreatReport> searchTrie(TrieNode root, String prefix) {
        TrieNode current = root;
        for (int i = 0; i < prefix.length(); i++) {
            current = current.children.get(Character.valueOf(prefix.charAt(i)));
            if (current == null) {
                return new HashSet<>();
            }
        }
        return new HashSet<>(current.reports);
    }

    /**
     * Time: O(l), where l is value length.
     * Space: O(1).
     * Reason: Walks the stored value path and removes one report from each node.
     */
    private void removeTrieReport(TrieNode root, String value, ThreatReport report) {
        TrieNode current = root;
        current.reports.remove(report);
        for (int i = 0; i < value.length(); i++) {
            current = current.children.get(Character.valueOf(value.charAt(i)));
            if (current == null) {
                return;
            }
            current.reports.remove(report);
        }
    }

    /**
     * Time: O(l), where l is string length.
     * Space: O(l), for the reversed string.
     * Reason: Builds a new string by reading characters backward.
     */
    private String reverse(String value) {
        StringBuilder builder = new StringBuilder();
        for (int i = value.length() - 1; i >= 0; i--) {
            builder.append(value.charAt(i));
        }
        return builder.toString();
    }

    /**
     * Time: O(r^2), where r is report count.
     * Space: O(r), for the returned list.
     * Reason: Copies reports, then uses insertion sort for deterministic order.
     */
    private List<ThreatReport> sortedReports(Set<ThreatReport> reports) {
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

    private static class TrieNode {
        private final Map<Character, TrieNode> children = new HashMap<>();
        private final Set<ThreatReport> reports = new HashSet<>();
    }
}
