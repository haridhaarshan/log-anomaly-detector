import java.util.List;

/**
 * Every detection rule implements this interface.
 * To add a new rule, create a class that implements Detector
 * and add it to the list in Main. Nothing else needs to change.
 */
public interface Detector {
    List<Alert> detect(List<LogEvent> events);
}
