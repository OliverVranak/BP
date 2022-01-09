from stegano import *
import base64

#opens binary file and encypts it with base64
with open("./bigrams","rb") as bin_file:
    encoded_string = base64.b64encode(bin_file.read())

message = encoded_string.decode()
print(message)
#hiding string into png file using LSB technique
secret = lsb.hide("./image.png",message)
#saving the picture containing the message
secret.save("./secret_image.png")

#exctracting the file from picture
output = lsb.reveal("./secret_image.png")
output += "==="
#decoding back to binary from base64
output = base64.b64decode(output)
#writing binary into a file
with open("./secret","wb") as file:
    file.write(output)
print(output)
