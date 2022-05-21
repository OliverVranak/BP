### Requirements
For the proper functioning.
It is necessary to have Python 3.x and installed below stated libraries.
* pip install stegano
* pip install -U scikit-learn
* pip install pefile
* pip install pyelftools
* pip install pyfiglet
-----------------------------------------------------
### Important
Because the trained models are not included, during the first run all models will be trained so it can take some time.
Also during the training you will be able to see the acurracy and false positive rate of each algorithm.
After the first run, all models will be available.

### Testing

Images **image_exe.png , image_no_header_file.png , image_pdf.png** are available 
for testing the main part of this project, the **Analysis of picture**.

During Analysis, various reports will be saved so the terminal is not messy.
* report - consists of basic information about the architecture, filetype, the most frequent opcodes and also informations from VirusTotal
* secret_file_disassemble - consists of the full disassembled version of the extracted file
* secret_file - exctracted file from a picture

Besides, feel free to play around and suggest ideas for a possible upgrade.
