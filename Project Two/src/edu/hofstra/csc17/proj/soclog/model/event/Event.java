package edu.hofstra.csc17.proj.soclog.model.event;

import java.time.Instant;
import java.util.Objects;

import edu.hofstra.csc17.proj.soclog.model.entity.ObjectInfo;
import edu.hofstra.csc17.proj.soclog.model.entity.ProcessInfo;

/**
 * Immutable base type for all normalized log events.
 */
public abstract class Event {
    private final EventType type;
    private final Instant timestamp;
    private final ProcessInfo subject;
    private final ObjectInfo object;
    private final String flags;

    protected Event(EventType type,
                    Instant timestamp,
                    ProcessInfo subject,
                    ObjectInfo object,
                    String flags) {
        this.type = type;
        this.timestamp = timestamp;
        this.subject = subject;
        this.object = object;
        this.flags = flags;
    }

    public EventType getType() {
        return type;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public ProcessInfo getSubject() {
        return subject;
    }

    public ObjectInfo getObject() {
        return object;
    }

    public String getFlags() {
        return flags;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        Event event = (Event) o;
        return Objects.equals(type, event.type)
                && Objects.equals(timestamp, event.timestamp)
                && Objects.equals(subject, event.subject)
                && Objects.equals(object, event.object)
                && Objects.equals(flags, event.flags);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, timestamp, subject, object, flags);
    }

    @Override
    public String toString() {
        return "Event{"
                + "type='" + type + '\''
                + ", timestamp=" + timestamp
                + ", subject=" + subject
                + ", object=" + object
                + ", flags='" + flags + '\''
                + '}';
    }
}
