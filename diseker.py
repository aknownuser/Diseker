import sys, getopt, os
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
                "Example: diseker.py -i /full/path/binary_to_analyse -c /full/path/config_file"
    else:
        use = "[Usage] diseker.py -i /full/path/binary_to_analyse -c /full/path/config_file"

    return use


def main(argv):
    binary_file = ""
    config_file = ""
    force = False
    short_opt ="hi:c:f"
    long_opt =["help", "input", "config", "force"]

    try:
        opts, args = getopt.getopt(argv, short_opt, long_opt)
    except getopt.error as err:
        print(str(err))
        print(usage(full=False))
        sys.exit(1)

    # Get the options
    for opt, arg in opts:
        if opt in ["-h", "--help"]:
            print(usage(full=True))
            sys.exit(0)
        elif opt in ["-i", "--input"]:
            if os.path.exists(arg):
                binary_file = arg
            else:
                print("ERROR: The input file does not exist, try putting the full path")
                sys.exit(2)

        elif opt in ["-c", "--config"]:
            if os.path.exists(arg):
                config_file = arg
            else:
                print("ERROR: The configuration file does not exist, try putting the full path")
                sys.exit(2)
        elif opt in ["-f", "--force"]:
            force = True

    print("Starting the sandbox")

    orch = Orchestrator.Orchestrator(3, config_file)

    ret = orch.execute_once({"file": binary_file, "force": force})
    print("Sandbox finished, the results can be found at")
    print(ret)


if __name__ == '__main__':
    main(sys.argv[1:])
