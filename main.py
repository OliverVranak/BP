from tools.encode_file import *
from tools.reveal_file import *
from tools.virus_total import *
from tools.analysis import *

def switch(choice):
    if choice == 1:
        encode_file_into_picture()
    elif choice == 2:
        reveal_file_from_picture()
    elif choice == 3:
        analyze()
    else:
        sys.exit(0)

if __name__ == "__main__":
    while True:
        print("\n\nChoose from the options below:")
        print("     1)Encode file into picture")
        print("     2)Reveal file from a picture")
        print("     3)Analyze picture")
        print("     4)Exit")
        choice = int(input("Input:  "))

        switch(choice)



