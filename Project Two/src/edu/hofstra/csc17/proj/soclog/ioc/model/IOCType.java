package edu.hofstra.csc17.proj.soclog.ioc.model;

/**
 * Types of Indicators of Compromise (IOCs) extracted from security events.
 * IOCs are artifacts that indicate potential security incidents or malicious activity.
 */
public enum IOCType {
    /** IP address (e.g., 192.168.1.100) */
    IP_ADDRESS,

    /** Domain name (e.g., evil.com, malware-cdn.net) */
    DOMAIN,

    /** File hash (MD5, SHA1, SHA256, etc.) */
    FILE_HASH,

    /** Process or executable name (e.g., malware.exe, cryptominer) */
    PROCESS_NAME,

    /** Full URL (e.g., http://evil.com/payload.exe) */
    URL,

    /** Email address */
    EMAIL,

    /** Windows registry key path */
    REGISTRY_KEY,

    /** Mutex name (synchronization primitive used by malware) */
    MUTEX,

    /** File path (e.g., /tmp/malware.sh) */
    FILE_PATH
}
