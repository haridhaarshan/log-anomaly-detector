/** A suspicious finding raised by a detector. */
public class Alert implements Comparable<Alert> {

    public enum Risk { LOW, MEDIUM, HIGH }

    private final String type;
    private final Risk risk;
    private final String message;

    public Alert(String type, Risk risk, String message) {
        this.type = type;
        this.risk = risk;
        this.message = message;
    }

    public String getType() { return type; }
    public Risk getRisk() { return risk; }
    public String getMessage() { return message; }

    /** Sorts alerts so that HIGH risk comes first. */
    @Override
    public int compareTo(Alert other) {
        return other.risk.compareTo(this.risk);
    }

    @Override
    public String toString() {
        return "[" + risk + "] " + type + ": " + message;
    }
}
