# arpnotifier
Python script that uses the [Scapy](https://scapy.net/) library.
The script analyse the syslog messages created by [Arpwatch](https://linux.die.net/man/8/arpwatch) and send to the machine with the IP notified in the log(that is performing possible malicious operations) a message to notify the anomaly found.
The message that is sent is a an ethernet frame type 0101 with a modified payload.

## Usage
Run the tool by simply launching it in the following way
```
python3 arpnotifier.py
```
or
```
./arpnotifier.py
```
after adding execution permissions(chmod +x avoidhandshakes.py).

## Authors
[Nicola Bottura](https://github.com/NicolaBottura)

@Giuseppe D'Agostino
