from rules import detect_port_scan

# Test 1: 10 unique ports should trigger detection
ports_10 = [21, 22, 23, 25, 53, 80, 110, 143, 443, 8080]
assert detect_port_scan("192.168.1.10", ports_10) is True
print("Test 1 PASS: 10 unique ports detected")

# Test 2: 9 unique ports should not trigger detection
ports_9 = [21, 22, 23, 25, 53, 80, 110, 143, 443]
assert detect_port_scan("192.168.1.10", ports_9) is False
print("Test 2 PASS: 9 unique ports not detected")

# Test 3: Duplicate ports should not count as new ports
duplicate_ports = [80, 80, 80, 443, 443, 22, 22, 53, 53, 21]
assert detect_port_scan("192.168.1.10", duplicate_ports) is False
print("Test 3 PASS: Duplicate ports handled correctly")

print("\nAll port scan threshold tests passed!")