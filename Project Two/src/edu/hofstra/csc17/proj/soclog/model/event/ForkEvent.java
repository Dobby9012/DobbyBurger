package edu.hofstra.csc17.proj.soclog.model.event;

import java.time.Instant;

import edu.hofstra.csc17.proj.soclog.model.entity.ProcessInfo;

/**
 * Represents a process fork operation.
 * In this event type, both subject and object are ProcessInfo instances:
 * - subject: the parent process that is forking
 * - object: the child process being created
 */
public class ForkEvent extends Event {

    public ForkEvent(Instant timestamp, ProcessInfo parentProcess, ProcessInfo childProcess, String flags) {
        super(EventType.fork, timestamp, parentProcess, childProcess, flags);
        if (timestamp == null) {
            throw new IllegalArgumentException("Timestamp cannot be null");
        }
        if (parentProcess == null) {
            throw new IllegalArgumentException("Parent process cannot be null");
        }
        if (childProcess == null) {
            throw new IllegalArgumentException("Child process cannot be null");
        }
    }

    /**
     * Get the parent process that initiated the fork.
     */
    public ProcessInfo getParentProcess() {
        return getSubject();
    }

    /**
     * Get the child process that was created by the fork.
     */
    public ProcessInfo getChildProcess() {
        return (ProcessInfo) getObject();
    }

}