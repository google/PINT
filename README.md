# PINT (Platform Integrity)

PINT is a set of formats and protocols for attesting and securing platform software
in datacenter environments. This includes:

* Peripheral (GPU, NIC, etc.) firmware
* Main board firmware (BIOS)
* Operating system components (bootloader, kernel, system services)

## Projects

PINT currently defines the following primitives for securing system software:

| Project Name                            | Description |
| --------------------------------------- | ----------- |
| [Firmware Measurement Descriptor](fmd/) | A binary header which describes how an Root of Trust should measure a firmware image |
