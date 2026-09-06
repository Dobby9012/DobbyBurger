package edu.hofstra.csc17.proj.soclog.ioc.model;

import java.util.Objects;

/**
 * Represents an Indicator of Compromise (IOC).
 * IOCs are artifacts or observables that indicate potential security threats.
 * They are extracted from security events for threat intelligence analysis.
 */
public class IOC {
    private final String value;
    private final IOCType type;
    private final String source; // Optional: where this IOC was observed

    /**
     * Creates a new IOC.
     *
     * @param value The IOC value (e.g., "192.168.1.100", "evil.com", "abc123...")
     * @param type The type of IOC
     * @throws IllegalArgumentException if value is null or empty, or type is null
     */
    public IOC(String value, IOCType type) {
        this(value, type, null);
    }

    /**
     * Creates a new IOC with source information.
     *
     * @param value The IOC value
     * @param type The type of IOC
     * @param source Optional source/context (e.g., "network_traffic", "file_system")
     */
    public IOC(String value, IOCType type, String source) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("IOC value cannot be null or empty");
        }
        if (type == null) {
            throw new IllegalArgumentException("IOC type cannot be null");
        }

        this.value = value.trim();
        this.type = type;
        this.source = source;
    }

    public String getValue() {
        return value;
    }

    public IOCType getType() {
        return type;
    }

    public String getSource() {
        return source;
    }

    /**
     * Normalizes the IOC value for matching purposes.
     * - Domains and IPs are lowercased
     * - File hashes are lowercased
     * - Process names are lowercased (Windows is case-insensitive)
     * - URLs are lowercased
     *
     * @return Normalized IOC value
     */
    public String getNormalizedValue() {
        switch (type) {
            case IP_ADDRESS:
            case DOMAIN:
            case FILE_HASH:
            case PROCESS_NAME:
            case EMAIL:
            case URL:
                return value.toLowerCase();
            case FILE_PATH:
            case REGISTRY_KEY:
            case MUTEX:
            default:
                return value;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        IOC ioc = (IOC) o;
        return getNormalizedValue().equals(ioc.getNormalizedValue()) && type == ioc.type;
    }

    @Override
    public int hashCode() {
        return Objects.hash(getNormalizedValue(), type);
    }

    @Override
    public String toString() {
        return String.format("IOC{type=%s, value='%s'%s}",
                type, value, source != null ? ", source='" + source + "'" : "");
    }
}
