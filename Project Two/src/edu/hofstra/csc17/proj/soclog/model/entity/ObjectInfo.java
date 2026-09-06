package edu.hofstra.csc17.proj.soclog.model.entity;

/**
 * Abstract base class for all event object types (FileInfo, NetworkInfo, etc.).
 * Provides common functionality for event objects that can be referenced in log events.
 */
public abstract class ObjectInfo {

    /**
     * Returns a human-readable display name for this object.
     * Used for logging, debugging, and user interfaces.
     */
    public abstract String getDisplayName();

    /**
     * Returns the canonical identifier for this object.
     * Used for deduplication and frequency analysis.
     */
    public abstract String getCanonicalId();
}