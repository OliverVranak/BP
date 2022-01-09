from stegano import *
import base64


with open("./bigrams","rb") as bin_file:
    encoded_string = base64.b64encode(bin_file.read())

message = encoded_string.decode()
print(message)
secret = lsb.hide("./image.png",message)
secret.save("./secret_image.png")

output = lsb.reveal("./secret_image.png")
output += "==="
output = base64.b64decode(output)
with open("./secret","wb") as file:
    file.write(output)
print(output)
