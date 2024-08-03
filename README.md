# pcapng_pp

Warning: this library is still in development.

Simple library for reading/writing pcapng files.

At this moment only reading is implemented.

# Reading usage example:

```
FileReader reader("file.pcapng");
while (auto packet = reader.read_packet()) {
    auto packet_data = packet.value().get_packet_data();
    // do something with packet data
}
// when got here, then EOF reached
```
