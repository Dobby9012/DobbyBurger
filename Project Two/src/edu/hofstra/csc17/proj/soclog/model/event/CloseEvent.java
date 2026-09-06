package edu.hofstra.csc17.proj.soclog.model.event;

import java.time.Instant;

import edu.hofstra.csc17.proj.soclog.model.entity.ObjectInfo;
import edu.hofstra.csc17.proj.soclog.model.entity.ProcessInfo;

/**
 * Represents a file/resource close operation.
 */
public class CloseEvent extends Event {

    public CloseEvent(Instant timestamp, ProcessInfo subject, ObjectInfo object, String flags) {
        super(EventType.close, timestamp, subject, object, flags);
        if (timestamp == null) {
            throw new IllegalArgumentException("Timestamp cannot be null");
        }
        if (subject == null) {
            throw new IllegalArgumentException("Subject cannot be null");
        }
        if (object == null) {
            throw new IllegalArgumentException("Object cannot be null");
        }
    }

}