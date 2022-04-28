from datetime import datetime
import filetype
import struct
import os

magic_numbers = {
                 'png': bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
                 'jpg': bytes([0xFF, 0xD8, 0xFF, 0xE0]),
                 'BMP': bytes([0x42, 0x4D]),
                 'GIF': bytes([0x47, 0x49, 0x46, 0x38, 0x37, 0x61]),
                 'doc': bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]),
                 'xls': bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]),
                 'ppt': bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]),
                 'docx': bytes([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00]),
                 'zip': bytes([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00]),
                 'xlsx': bytes([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00]),
                 'csv': bytes([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00]),
                 'pptx': bytes([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00]),
                 'pdf': bytes([0x25, 0x50, 0x44, 0x46]),
                 'dll': bytes([0x4D, 0x5A, 0x90, 0x00]),
                 'exe': bytes([0x4D, 0x5A]),
                 'ELF': bytes([0x7F, 0x45, 0x4C, 0x46]),
                 'Rar': bytes([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]),
                 'pcap': bytes([0xA1, 0xB2, 0x3C, 0x4D]),
                 'txt': bytes([0xEF, 0xBB, 0xBF]),
                 }

def check_architecture(report):
    IMAGE_FILE_MACHINE_I386 = 332
    IMAGE_FILE_MACHINE_IA64 = 512
    IMAGE_FILE_MACHINE_AMD64 = 34404
    IMAGE_FILE_MACHINE_ARM = 452
    IMAGE_FILE_MACHINE_AARCH64 = 43620

    with open("secret_file","rb") as file:
        header = file.read(2)
        if header == b'MZ':
            file.seek(60)
            header = file.read(4)
            header_offset = struct.unpack("<L",header)[0]
            file.seek(header_offset+4)
            header = file.read(2)
            arch = struct.unpack("<H",header)[0]

            if arch == IMAGE_FILE_MACHINE_I386:
                report.write("Architecture: IA-32 (32-bit x86)\n")
            elif arch == IMAGE_FILE_MACHINE_IA64:
                report.write("Architecture: IA-64 (Itanium)\n")
            elif arch == IMAGE_FILE_MACHINE_AMD64:
                report.write("Architecture: AMD64 (64-bit x86)\n")
            elif arch == IMAGE_FILE_MACHINE_ARM:
                report.write("Architecture: ARM eabi (32-bit)\n")
            elif arch == IMAGE_FILE_MACHINE_AARCH64:
                report.write("Architecture: AArch64 (ARM-64, 64-bit)\n")
            else:
                report.write("Architecture: Unknown\n")

    file.close()

def check_filetype(file):
    if os.path.exists('report'):
        os.remove('report')
    with open("report","a+") as report:
        report.write("-- IMAGE SCANNER --")
        report.write('\n\n\n')
        print("[*][" + datetime.now().strftime("%H:%M:%S") + "] Checking filetype...")
        possible_file_type = list()
        # figuring out filetype of extracted file
        file_type = filetype.guess('secret_file')
        # checking the architecture of file
        check_architecture(report)

        if file_type is None:
            report.write("Filetype: Unknown\n")
            print("[+][" + datetime.now().strftime("%H:%M:%S") + "] Unknown filetype")
            # library filetype does not contain all extensions
            # for that reason we run through our dictionary of extensions for possible match
            for i in magic_numbers:
                if file.startswith(magic_numbers[i]):
                    possible_file_type.append(i)
            # if we found a match it will display it
            report.write("Possible filetypes: ")
            if len(possible_file_type) != 0:
                print("[+][" + datetime.now().strftime("%H:%M:%S") + "] Possible File extensions: ", end=" ")
                for i in possible_file_type:
                    print(i, end=" ")
                    report.write(i)
                print()
            # no known filetype
            report.write('\n')
            if len(possible_file_type) == 0:
                report.close()
                return 1
            elif "ELF" in possible_file_type or "dll" in possible_file_type or "exe" in possible_file_type:
                report.close()
                return 1
            else:
                report.close()
                return 0

        else:
            report.write("Filetype: {}\n".format(str(file_type.extension)))
            report.write("FileMIME: {}\n".format(str(file_type.mime)))
            print("[+][" + datetime.now().strftime("%H:%M:%S") + "] File extension is: " + str(file_type.extension))
            print("[+][" + datetime.now().strftime("%H:%M:%S") + "] FileMIME is: " + str(file_type.mime))

            if str(file_type.extension) == "exe" or str(file_type.extension) == "elf" or str(file_type.extension) == "dll":
                report.close()
                return 1
            else:
                report.close()
                return 0


