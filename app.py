# Python implementation of 1 Assymentric and 2 Symmetric encryption algorithms
import RSA
import Blowfish
import DES
# Simple menu to choose the encryption algorithm
def main():
    choice = input("Choose an encryption algorithm (RSA, DES, Blowfish): ")
    if choice == "RSA":
        RSA.start()
    elif choice == "Blowfish":
        Blowfish.start()
    elif choice == "DES":
        DES.start()
    else:
        print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()