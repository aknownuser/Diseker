# Diseker Sandbox

## Description

Diseker Sandbox is a simple contained environment for executing and analyzing IoT malware. It provides the necessary tools to extract malware functionality and present it to the user.

## Usage

diseker.py -i /full/path/binary_to_analyse -c /full/path/config_file

### Options

*  `-i`, `--input`:  Specifies the full path to the binary file to be analyzed.
*  `-c`, `--config`: Specifies the full path to the configuration file. This file contains information for starting emulators, database settings, and output directory configuration.
*  `-f`, `--force`: Forces the emulator to execute the file even if it is found in the database.
*  `-a`, `--arch`:  Specifies the architecture of the device (aarch64, ppc64, x86_64, x86, arm).
*  `-b`, `--bits`: Specifies the number of bits in the architecture (32 or 64).
*  `-t`, `--time`:  Specifies the execution time in seconds (default is 120.0).
*  `-o`, `--out`: Specifies the destination folder for the output (default is the current directory).

### Example

diseker.py -i /full/path/binary_to_analyse -c /full/path/config_file -a arm -b 32 -t 180 -o /path/to/output

## Configuration File

The configuration file should contain the following information:

*  Emulator settings (e.g., type, path, command-line options)
*  Database connection details (e.g., host, port, username, password)
*  Output directory path

## Output

The sandbox generates various output files, including:

*  Dynamic analysis reports (e.g., system calls, network activity)
*  Static analysis reports (e.g., strings, imports)
*  Screenshots and videos of the malware execution

The output is saved in the specified destination folder.

## Dependencies

* Python 3.6 or higher
* Required Python packages (install using `pip install -r requirements.txt`):
    * argparse

## Contributing

Contributions are welcome! Please submit bug reports and feature requests through the issue tracker.
