import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/** One parsed line of an authentication log. */
public class LogEvent {
    public static final DateTimeFormatter FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final LocalDateTime timestamp;
    private final String ip;
    private final String username;
    private final boolean success;

    public LogEvent(LocalDateTime timestamp, String ip, String username, boolean success) {
        this.timestamp = timestamp;
        this.ip = ip;
        this.username = username;
        this.success = success;
    }

    public LocalDateTime getTimestamp() { return timestamp; }
    public String getIp() { return ip; }
    public String getUsername() { return username; }
    public boolean isSuccess() { return success; }

    /** Converts the event back into a CSV line. */
    public String toCsv() {
        return timestamp.format(FORMAT) + "," + ip + "," + username + ","
                + (success ? "SUCCESS" : "FAIL");
    }
}
