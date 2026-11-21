import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Flags a user who logs in successfully from many different IP addresses.
 * A normal user has one or two; many can mean a stolen password.
 */
public class AccountSpreadDetector implements Detector {

    private final int ipThreshold;

    public AccountSpreadDetector(int ipThreshold) {
        this.ipThreshold = ipThreshold;
    }

    @Override
    public List<Alert> detect(List<LogEvent> events) {
        Map<String, Set<String>> ipsByUser = new HashMap<>();
        for (LogEvent e : events) {
            if (e.isSuccess()) {
                ipsByUser.computeIfAbsent(e.getUsername(), k -> new HashSet<>())
                         .add(e.getIp());
            }
        }

        List<Alert> alerts = new ArrayList<>();
        for (Map.Entry<String, Set<String>> entry : ipsByUser.entrySet()) {
            int count = entry.getValue().size();
            if (count >= ipThreshold) {
                alerts.add(new Alert("Account spreading", Alert.Risk.HIGH,
                        entry.getKey() + " logged in from " + count
                        + " different IPs: " + entry.getValue()));
            }
        }
        return alerts;
    }
}
