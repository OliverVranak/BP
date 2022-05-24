### Requirements
For the proper functioning.
It is necessary to have Python 3.x and installed below stated libraries.
* pip install stegano
* pip install -U scikit-learn
* pip install pefile
* pip install pyelftools
* pip install pyfiglet
* pip install capstone
-----------------------------------------------------

### Testing

Images **image_exe.png , image_no_header_file.png , image_pdf.png** are available 
for testing the main part of this project, the **Analysis of picture**.

During Analysis, various reports will be saved so the terminal is not messy.
* report - consists of basic information about the architecture, filetype, the most frequent opcodes and also informations from VirusTotal
* secret_file_disassemble - consists of the full disassembled version of the extracted file
* secret_file - exctracted file from a picture

Besides, feel free to play around and suggest ideas for a possible upgrade.
