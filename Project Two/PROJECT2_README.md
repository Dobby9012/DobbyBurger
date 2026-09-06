# Project 2: Threat Intelligence & IOC Analysis System

## Project Overview

Building on Project 1's log parsing and analysis toolkit, you'll extend the SOC capabilities with **threat intelligence integration** and **advanced data structures** for fast IOC (Indicator of Compromise) lookups.

**Scenario**: Your SOC team receives daily threat intelligence reports containing known malicious indicators (IPs, domains, file hashes, process names). You need to:
1. Parse threat intelligence reports from CSV files
2. Build efficient data structures for fast IOC matching
3. Correlate live security events against known threats
4. Perform advanced threat analysis using inverted indexes

This project teaches you how real SOC systems perform threat detection at scale using optimized data structures.

---

## Architecture Overview

The threat intelligence system has three main components:

### Component 1: Threat Intelligence Parsing
**ThreatReportParser** reads threat reports from CSV and extracts IOCs (Indicators of Compromise). *(Already implemented)*

### Component 2: IOC Matching Engine
**IOCMatcher** matches live security events against known malicious indicators using fast lookup structures.

### Component 3: Inverted Index & Analytics
**InvertedIndex** + **AnalyticsEngine** provide fast exact lookups and efficient prefix searches.


---

## Task 1: IOC Matcher

### Class: `IOCMatcher.java`

#### **Constructor: `IOCMatcher(List<IOC> knownIOCs)`** - **[IMPLEMENT THIS]**

Build an internal index for fast IOC matching.

**Purpose**: When an event arrives, quickly check "is this IP address in our threat list?"

---

#### **Method: `matchEvent(Event event)`** - **[IMPLEMENT THIS]**

Match a single security event against known IOCs.

**What to extract from events**:
- Process name from `event.getSubject()`
- IP address from network events (sendto/receivefrom)
- File path from file events (read/write/execute/open)

**Return**: List of matched IOCs found in the event

**Hints**:
- Normalize values before comparing (case-insensitive)

---

## Task 2: Inverted Index

### Class: `InvertedIndex.java`

The Inverted Index provides fast threat intelligence lookups. You need to choose and implement appropriate data structures to support:
- Fast exact IOC lookups
- Efficient prefix searching for domains and IP addresses

**Design Challenge**: What data structures provide these capabilities efficiently?

---

#### **Method: `indexReport(ThreatReport report)`** - **[IMPLEMENT THIS]**

Index a single threat report for fast searching.

**Requirements**:
- Store the report for later retrieval
- Enable fast exact lookups by IOC value
- Support prefix searching for domains and IP addresses

---

#### **Method: `searchExact(IOC ioc)`** - **[IMPLEMENT THIS]**

Search for threat reports containing an exact IOC match.

**Goal**: Fast lookups by exact IOC value

---

#### **Method: `searchPrefix(String prefix, IOCType type)`** - **[IMPLEMENT THIS]**

Search for threat reports containing IOCs matching a prefix pattern.

**Examples**:
- "192.168." should find all IPs starting with "192.168."
- "evil" should find domains starting with "evil"

---

#### **Method: `getReportCount()`** - **[IMPLEMENT THIS]**

Get the total number of indexed reports.

---

#### **Method:`removeReport()`** - **[IMPLEMENT THIS]**

Remove a report from the index.

---

#### **Method: `getUniqueIOCCount()`** - **[IMPLEMENT THIS]**

Get the total number of unique IOCs indexed.

---

## Task 3: Analytics Engine IOC Methods

### Class: `AnalyticsEngine.java`

---

#### **Method: `extractAllIOCs()`** - **[IMPLEMENT THIS]**

Extract all unique IOCs from the event dataset.

---

#### **Method: `extractIOCs(Instant startInclusive, Instant endInclusive)`** - **[IMPLEMENT THIS]**

Extract IOCs from events within a time window.

---

#### **Method: `findEventsWithIOC(IOC ioc)`** - **[IMPLEMENT THIS]**

Find all events containing a specific IOC.

---

#### **Method: `findTopIOCs(int limit)`** - **[IMPLEMENT THIS]**

Find the most frequently observed IOCs.

---

#### **Method: `buildThreatIntelligenceIndex(List<ThreatReport> threatReports)`** - **[IMPLEMENT THIS]**

Build an inverted index from threat reports.

---

#### **Method: `findThreatsUsingIndex(InvertedIndex index)`** - **[IMPLEMENT THIS]**

Correlate events with threat reports using inverted index.

**This is the payoff!** Fast threat correlation using your optimized data structures

---

#### **Method: `findEventsWithPrefixPattern(InvertedIndex index, String prefix, IOCType type)`** - **[IMPLEMENT THIS]**

Find events matching a prefix pattern using the inverted index.

---

#### **Method: `findEventsInSubnet(String subnetPrefix)`** - **[IMPLEMENT THIS]**

Find network events in a specific IP subnet.


---

#### **Method: `bulkIOCLookup(InvertedIndex index, List<IOC> iocs)`** - **[IMPLEMENT THIS]**

Perform bulk IOC lookups using inverted index.


---

## Data Files

### Input: `data/threat_reports.csv`

CSV format for threat intelligence reports:
```
RPT001,2024-01-15T10:30:00Z,IP_ADDRESS,192.168.1.100,HIGH,APT28,Command and control server for backdoor malware
RPT001,2024-01-15T10:30:00Z,FILE_HASH,a1b2c3d4e5f6,HIGH,APT28,Command and control server for backdoor malware
RPT002,2024-01-16T14:22:00Z,DOMAIN,malware-cdn.net,MEDIUM,Unknown,Distribution site for ransomware payload
```

**Note**: Multiple rows with same `report_id` are aggregated into one ThreatReport object with multiple IOCs.

---

## Testing Requirements

### Coverage Targets
- **Unit testing**: Test each TODO method independently
- **Integration testing**: Test full threat correlation workflow in Main
- **Edge cases**: Empty inputs, null values, large datasets

---

## Complexity Analysis Requirements

For each method you implement, document the time and space complexity.

**Example format**:
```java
/**
 * Time Complexity: O(m) where m = string length
 * Space Complexity: O(m) for recursive call stack
 * Justification: Trie insertion traverses each character once.
 */
```

---

## Submission

### Code Submission (Gradescope)
- Submit ZIP of `/src` folder
- Exclude build artifacts (`/bin`, `.class` files)
- Ensure all TODO methods are implemented
- Include test files

---

## Grading Rubric

### Implementation (50%)

### Design & Analysis (25%)
- **Complexity Analysis** : Big-O analysis
- **Design Decisions** : Justified choices
- **Documentation** : Clear comments

### Testing (25%)
- **Coverage** : All methods tested
- **Edge Cases** : Null, empty, boundary conditions
- **Integration Tests** : End-to-end workflow

---

## Getting Started

### Recommended Implementation Order

**Phase 1: Basic Structures**
1. IOCMatcher
3. AnalyticsEngine.extractAllIOCs

**Phase 2: Inverted Index Core**
4. Design and implement data structures for InvertedIndex
5. InvertedIndex.indexReport

**Phase 3: Search Operations**
6. InvertedIndex.searchExact
7. InvertedIndex.searchPrefix
8. InvertedIndex.getReportCount and getUniqueIOCCount

**Phase 4: Analytics Integration**
9. AnalyticsEngine.buildThreatIntelligenceIndex
10. AnalyticsEngine.findThreatsUsingIndex
11. Remaining AnalyticsEngine methods

---

## Data Structure Design Considerations

When implementing the InvertedIndex, consider:
- **Exact matching**: What provides constant-time lookups?
- **Prefix searching**: What enables efficient prefix pattern matching?
- **Memory efficiency**: How can you avoid storing duplicate data?
- **Time complexity**: What are the performance requirements for each operation?

You should justify your data structure choices in code comments with complexity analysis.
