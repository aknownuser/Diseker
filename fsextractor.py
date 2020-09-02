import os
import subprocess
import time
import magic
import yaml

def extract(file_path):
    DECIMAL = 0
    FILESYSTEM=1 # "Squashfs"
    DEST_PATH= os.path.splitext(os.path.basename(file_path))[0]
    binwalk_call = subprocess.run(["binwalk", file_path], stdout=subprocess.PIPE)
    binwalk_result =str(binwalk_call.stdout).split('\\n')[3:-2]

    cnt = len(binwalk_result) - 1
    while cnt >= 0:
        if "filesystem" in binwalk_result[cnt] and cnt == len(binwalk_result)-1:
            DECIMAL = int(binwalk_result[cnt].split(' ')[0])
            break

    if DECIMAL != 0:
        subprocess.run(["mkdir", DEST_PATH])
        subprocess.run(["dd", "bs=1","skip="+str(DECIMAL),"if="+str(file_path), "of="+DEST_PATH+"/filesystem"])
        time.sleep(2)
        paths_check=["/usr", "/bin", "/sbin"]
        if FILESYSTEM == 1:
            os.system("unsquashfs -f -d "+DEST_PATH+"/fs "+DEST_PATH+"/filesystem")
            root_path=DEST_PATH+"/fs/usr"

            for dirName, subdirList, fileList in os.walk(root_path, topdown=False):
                if len(fileList) != 0:
                    for file in fileList:
                        subprocess.run(["file", file])

        return DEST_PATH+"/fs"


def start_emulator(fs_path, arch, cfg):

    sim = {"arm": "qemu-system-arm",
           "mips": "qemu-system-mips",
           "x86": "qemu-system-i386"}

    os.system("%s -M malta -kernel %s\
    -hda %s -append \"root=/dev/sda1 console=tty0\"" % (sim[arch], cfg["images"]["debian"]["kernel"], cfg["images"]["debian"]["image"]))


def _get_config():
    cfg = None
    with open("config.yml") as ymlfile:
        cfg = yaml.load(ymlfile)
    return cfg


def _get_arch(path):
    found_archs=["x86", "ARM", "MIPS"]
    for dirName, subdirList, fileList in os.walk(path, topdown=False):
        path=dirName.split(os.sep)
        for file in fileList:
            print(dirName+str(file))
            file_exec=subprocess.run(["file", dirName+"/"+file], stdout=subprocess.PIPE)
            rslt = _get_match(found_archs, str(file_exec.stdout))
            if rslt != "":
                return rslt


def _get_arch_dos(path):
    found_archs=["x86", "ARM", "MIPS"]
    for dirName, subdirList, fileList in os.walk(path, topdown=False):
        path=dirName.split(os.sep)
        for file in fileList:
            print(dirName+str(file))
            rslt = identify_platform(dirName+"/"+str(file))
            if rslt != "":
                return rslt


def identify_platform(filepath):
    filemagic = magic.Magic()
    filetype = ""
    try:
        #filetype = filemagic.id_filename(filepath)
        filetype = magic.from_file(filepath)
    except Exception as e:
        # certain version of libmagic throws error while parsing file, the CPU information is however included in the error in somecases
        filetype = str(e)
    #        filemagic.close()
    if "ELF 32-bit" in filetype:
        if "ARM" in filetype:
            return "ELF", "arm"
        if "80386" in filetype:
            return "ELF", "x86"
        if ("MIPS" in filetype) and ("MSB" in filetype):
            return "ELF", "mips"
        if "MIPS" in filetype:
            return "ELF", "mipsel"
        if "PowerPC" in filetype:
            return "ELF", "powerpc"
    if "ELF 64-bit" in filetype:
        if "x86-64" in filetype:
            return "ELF", "x86-64"
    return ""


def _get_match(values, origin):
    for val in values:
        if val in origin:
            return val
    return ""

if __name__ == "__main__":
    #extract("/home/pc/TFM/Dlink/DIR822C1_FW301WWb02.bin")
    cfg = _get_config()
    arch = _get_arch_dos("DIR822C1_FW301WWb02/fs/usr")
    print(arch)
    
    start_emulator("DIR822C1_FW301WWb02/fs/usr", arch[1], cfg)
