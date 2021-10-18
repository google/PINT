# Firmware Measurement Descriptor

The Firmware Measurement Descriptor (FMD) is a file header which provides
metadata about how the image should be measured (such as by a hardware
Root of Trust) during boot.

## Format and Design

See the [FMD design doc](doc/fmd_design_v0_3.pdf) for details about the
motivation, goals, and high level design concepts related to FMD.

## Reference Library

In addition to the descriptor format, a reference library is also provided for
creating and parsing the descriptor.

Source for the library can be found in the [lib](lib/) directory. Public
headers are in [inc/fmd](inc/fmd/).

### Samples

The [samples directory](samples/) contains example code which uses the
reference library to do common FMD-related tasks.

* **create\_parse**: Generate, serialize, and parse an FMD descriptor
