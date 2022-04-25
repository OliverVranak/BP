from tools.encode_file import *
from tools.analysis import *
from datetime import datetime
from pyfiglet import Figlet

def switch(choice):
    if choice == 1:
        encode_file_into_picture()
    elif choice == 2:
        reveal_file_from_picture()
    elif choice == 3:
        analyze()
    elif choice == 4:
        print("\n")
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] Shutting down...")
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] Good Bye.")
        exit(0)
    else:
        print("\n[+][" + datetime.now().strftime("%H:%M:%S") + "] Such option does not exist. Please try again")
        start()

def start():

    while True:
        print("\n\nChoose from the options below:\n")
        print("     [1] Encode file into picture")
        print("     [2] Reveal file from a picture")
        print("     [3] Analyze picture")
        print("     [4] Exit")
        try:
            choice = int(input("\nInput:  "))
            switch(choice)
        except ValueError:
            print("\n[+][" + datetime.now().strftime("%H:%M:%S") + "] Only numbers are allowed!")
            start()

if __name__ == "__main__":
    f = Figlet(font='slant')
    print("\n")
    print(f.renderText("IMAGE SCANNER"))
    start()



