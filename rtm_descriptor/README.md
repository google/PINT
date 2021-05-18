# Firmware Measurement Descriptor

The Firmware Measurement Descriptor (FMD) is a file header which provides
metadata about how the image should be measured (such as by a hardware
Root of Trust) during boot.

## Terms

* RTM: Root of Trust for Measurement
* Verifier: An entitiy which verifies measurements taken by an RTM
* TPM: Trusted Platform Module
* TLV: Type-Length-Value

## Measured Boot

In distributed systems, a common desire is to ensure a machine is in a
verifiably good state before allowing it to handle potentially sensitive
information. One way to solve this problem is through measured boot.

During boot, each piece of code, from system firmware to OS components, will
measure (take a hash of) the next component before transferring control. After
boot is complete, these measurements can be used to prove to a Verifier that what
code was booted on the system.

Take for example a standard UEFI Linux system which stores measurements in a
TPM:

1. UEFI hashes bootloader and extends hash into TPM, then executes bootloader
1. Bootloader hashes Linux kernel and extends hash into TPM, then executes Linux
1. After boot, userspace software can query TPM to get a Quote of the boot
   measurements


## Descriptor Format

### Structure Versioning

### TLV Structures

## Example Boot Process

## Reference Library

### Descriptor Creation

### Descriptor Parsing

### Library Versioning
