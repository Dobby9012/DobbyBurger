package edu.hofstra.csc17.proj.soclog.model.entity;

import java.util.Objects;


public final class ProcessInfo extends ObjectInfo {
    public static final String PRIV_USER = "user";
    public static final String PRIV_ROOT = "root";

    private final String name;
    private final Integer pid;
    private final String modulePath;
    private final String privilege;

    public ProcessInfo(String name, Integer pid, String modulePath, String privilege) {
        if (pid != null && pid < 0) {
            throw new IllegalArgumentException("PID must be non-negative, got: " + pid);
        }
        this.name = name;
        this.pid = pid;
        this.modulePath = modulePath;
        this.privilege = validatePrivilege(privilege);
    }

    private static String validatePrivilege(String privilege) {
        if (privilege != null && !PRIV_USER.equals(privilege) && !PRIV_ROOT.equals(privilege)) {
            throw new IllegalArgumentException("Privilege must be '" + PRIV_USER + "' or '" + PRIV_ROOT + "'");
        }
        return privilege;
    }

    public String getName() {
        return name;
    }

    public Integer getPid() {
        return pid;
    }

    public String getModulePath() {
        return modulePath;
    }

    public String getPath() {
        return modulePath;
    }

    public String getPrivilege() {
        return privilege;
    }

    public boolean isRoot() {
        return PRIV_ROOT.equals(privilege);
    }

    @Override
    public String getDisplayName() {
        if (name != null && !name.isEmpty()) {
            return name;
        }
        if (modulePath != null && !modulePath.isEmpty()) {
            return modulePath;
        }
        if (pid != null) {
            return "pid:" + pid;
        }
        return "<unknown-process>";
    }

    @Override
    public String getCanonicalId() {
        if (pid != null) {
            return "process:pid:" + pid;
        }
        if (name != null && !name.isEmpty()) {
            return "process:name:" + name;
        }
        if (modulePath != null && !modulePath.isEmpty()) {
            return "process:path:" + modulePath;
        }
        return "process:unknown";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        ProcessInfo that = (ProcessInfo) o;
        return Objects.equals(name, that.name)
                && Objects.equals(pid, that.pid)
                && Objects.equals(modulePath, that.modulePath)
                && Objects.equals(privilege, that.privilege);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, pid, modulePath, privilege);
    }

    @Override
    public String toString() {
        return "ProcessInfo{"
                + "name='" + name + '\''
                + ", pid=" + pid
                + ", modulePath='" + modulePath + '\''
                + ", privilege='" + privilege + '\''
                + '}';
    }
}
