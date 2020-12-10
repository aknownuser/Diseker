import sys, getopt, os
import argparse

import Orchestrator


def usage(full):
    use =""
    if full:
        use = "Diseker Sandbox is a simple contained environments for IoT malware to be executed.\n" \
              "It is equiped with the tools required to extract the malware functionality and present it to the user" \
              "The command line options:" \
              "-i / --input: holds the binary to be analysed (requires the full path)\n" \
              "-c / --config: holds the configuration file that containes all the information needed\n" \
              "to start the emulators, save the information in a database and the space where the resulting data\n" \
              "will be saved\n" \
              "-f / --force: forces the emulator to execute a file even if that file was found in the database\n" \
              "--cpu: Architecture of the device\n" \
              "-t / --time: Execution time\n" \
              "-b / --bits: Bits \n" \
              "-o / --out: Destination folder" \
                "Example: diseker.py -i /full/path/binary_to_analyse -c /full/path/config_file -p time arch bits"
    else:
        use = "[Usage] diseker.py -i /full/path/binary_to_analyse -c /full/path/config_file"

    return use


def main(argv):
    cmd = {}
    cmd["force"] = False
    cmd["arch"] = None
    cmd["bits"] = None
    cmd["out"] = "."

    parser = argparse.ArgumentParser(prog="diseker.py",
                                     description="Diseker Sandbox is a simple contained environments for IoT malware "
                                                 "to be executed. It is equiped with the tools required to extract "
                                                 "the malware functionality and present it to the user")
    parser.add_argument("-i", "--input", help="Holds the binary to be analysed (requires the full path)")
    parser.add_argument("-f", "--force", type=bool, default=False, help="Forces the emulator to execute a file even "
                                                                        "if that file was found in the database")
    parser.add_argument("-c", "--config", help="Configuration file to use")
    parser.add_argument("-a", "--arch", default=None, choices=["aarch64", "ppc64", "x86_64", "x86", "arm"],
                        help="Architecture of the file")

    parser.add_argument("-b", "--bits", default=None, type=int, choices=[32, 64],  help="Bits of architecture")
    parser.add_argument("-t", "--time", default=120.0, type=float, help="Execution time")
    parser.add_argument("-o", "--out", default=".", help="Destination path")

    args = parser.parse_args(argv)
    cmd = {}
    cmd["file"] = args.input
    cmd["force"] = args.force
    cmd["arch"] = args.arch
    cmd["bits"] = args.bits
    cmd["out"] = args.out
    cmd["time"] = args.time
    print("Starting the sandbox")
    print(cmd)

    orch = Orchestrator.Orchestrator(3, args.config)

    ret = orch.execute_once(cmd)
    print("Sandbox finished, the results can be found at")
    print(ret)


if __name__ == '__main__':
    main(sys.argv[1:])
