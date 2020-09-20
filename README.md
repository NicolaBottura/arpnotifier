# arpnotifier
Python script that take the syslog messages created by Arpwatch and send to the machine with the IP notified in the log(that's performing suspicious operations) an ethernet frame type 0101 with a modified payload - a message to notify the anomaly found.
