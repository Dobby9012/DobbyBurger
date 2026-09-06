package edu.hofstra.csc17.proj.soclog.model.entity;

import java.util.Objects;

/**
 * Represents network endpoint information for sendto/receivefrom events.
 */
public class NetworkInfo extends ObjectInfo {
    private final String ipAddress;
    private final int port;
    private final String protocol;

    public NetworkInfo(String ipAddress, int port, String protocol) {
        this.ipAddress = validateIP(ipAddress);
        this.port = validatePort(port);
        this.protocol = validateProtocol(protocol);
    }

    private static String validateIP(String ip) {
        if (ip == null) {
            throw new IllegalArgumentException("IP address cannot be null");
        }
        // Basic IPv4 validation
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            throw new IllegalArgumentException("Invalid IP address format: " + ip);
        }
        for (String part : parts) {
            try {
                int num = Integer.parseInt(part);
                if (num < 0 || num > 255) {
                    throw new IllegalArgumentException("Invalid IP address: " + ip);
                }
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid IP address: " + ip);
            }
        }
        return ip;
    }

    private static int validatePort(int port) {
        if (port < 0 || port > 65535) {
            throw new IllegalArgumentException("Port must be between 0 and 65535, got: " + port);
        }
        return port;
    }

    private static String validateProtocol(String protocol) {
        if (protocol == null) {
            throw new IllegalArgumentException("Protocol cannot be null");
        }
        if (!protocol.equals("TCP") && !protocol.equals("UDP") && !protocol.equals("ICMP")) {
            throw new IllegalArgumentException("Protocol must be TCP, UDP, or ICMP, got: " + protocol);
        }
        return protocol;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getIp() {
        return ipAddress;
    }

    public int getPort() {
        return port;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getEndpoint() {
        return ipAddress + ":" + port;
    }

    @Override
    public String getDisplayName() {
        return getEndpoint() + " (" + protocol + ")";
    }

    @Override
    public String getCanonicalId() {
        return "network:" + getEndpoint() + ":" + protocol;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NetworkInfo that = (NetworkInfo) o;
        return port == that.port &&
               Objects.equals(ipAddress, that.ipAddress) &&
               Objects.equals(protocol, that.protocol);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ipAddress, port, protocol);
    }

    @Override
    public String toString() {
        return "NetworkInfo{" +
               "endpoint='" + getEndpoint() + '\'' +
               ", protocol='" + protocol + '\'' +
               '}';
    }
}