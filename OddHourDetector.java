import java.util.ArrayList;
import java.util.List;

/** Flags successful logins that happen outside normal working hours. */
public class OddHourDetector implements Detector {

    private final int startHour; // logins before this hour are suspicious (e.g. 6)
    private final int endHour;   // logins at or after this hour are suspicious (e.g. 22)

    public OddHourDetector(int startHour, int endHour) {
        this.startHour = startHour;
        this.endHour = endHour;
    }

    @Override
    public List<Alert> detect(List<LogEvent> events) {
        List<Alert> alerts = new ArrayList<>();
        for (LogEvent e : events) {
            int hour = e.getTimestamp().getHour();
            if (e.isSuccess() && (hour < startHour || hour >= endHour)) {
                alerts.add(new Alert("Odd-hour login", Alert.Risk.MEDIUM,
                        e.getUsername() + " logged in successfully at "
                        + e.getTimestamp().format(LogEvent.FORMAT)
                        + " from " + e.getIp()));
            }
        }
        return alerts;
    }
}
