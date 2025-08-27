from tkinter import *
from tkinter import messagebox



def openNewWindow1():
    # Toplevel object which will
    # be treated as a new window
    newWindow = Toplevel(root)

    # sets the title of the
    # Toplevel widget
    newWindow.title("New Window")

    # sets the geometry of toplevel
    newWindow.geometry("600x600")

    def caesarencrypt(plaintext, n):
        ans = ""

        for i in range(len(plaintext)):
            ch = plaintext[i]

            if ch == " ":
                ans += " "

            elif (ch.isupper()):
                ans += chr((ord(ch) + n - 65) % 26 + 65)

            else:
                ans += chr((ord(ch) + n - 97) % 26 + 97)
        return ans

    def caesardecrypt(Ciphertext,n):

        letters = "abcdefghijklmnopqrstuvwxyz"

        decrypted_message = ""

        for ch in Ciphertext:

            if ch in letters:
                position = letters.find(ch)
                new_pos = (position - n) % 26
                new_char = letters[new_pos]
                decrypted_message += new_char
            else:
                decrypted_message += ch

        return decrypted_message

    def EncryptedMsg():
        Plaintext = PlainText.get()
        key1 = Key1.get()
        encrypted_msg = caesarencrypt(Plaintext, key1)
        print(encrypted_msg)
        messagebox.showinfo("Encrypted message", encrypted_msg)

    def DecryptedMsg():
        Ciphertext = CipherText.get()
        key2 = Key2.get()
        decrypted_msg = caesardecrypt(Ciphertext, key2)
        print(decrypted_msg)
        messagebox.showinfo("Decrypted message", decrypted_msg)

    PlainText = StringVar()
    Key1 = IntVar()
    CipherText = StringVar()
    Key2 = IntVar()

    #label for Caesar cipher Title
    lblInfo = Label(newWindow, font=('arial', 30, 'bold'), text="CAESAR CIPHER ALGORITHM", fg="green", bd=10,
                    anchor='w')
    lblInfo.grid(row=0, column=0)

    # label for Encryption
    lblEncryption = Label(newWindow, font=('arial', 20, 'bold'), text="ENCRYPTION", fg='blue', bd=16, anchor='w',
                          justify='center')
    lblEncryption.grid(row=1, column=1)

    # Label for Plain Text
    lblPlainText = Label(newWindow, font=('arial', 16, 'bold'), text="Plain Text", bd=16, anchor='w')
    lblPlainText.grid(row=2, column=0)
    lblPlainText = Entry(newWindow, font=('arial', 16, 'bold'), textvariable=PlainText, bd=10, insertwidth=4, bg="orange",
                         justify='right')
    lblPlainText.grid(row=2, column=1)

    #Label for key
    lblKey1 = Label(newWindow, font=('arial', 16, 'bold'), text="Key", bd=16, anchor='w')
    lblKey1.grid(row=3, column=0)
    lblKey1 = Entry(newWindow, font=('arial', 16, 'bold'), textvariable=Key1, bd=10, insertwidth=4, bg="orange", justify='right')
    lblKey1.grid(row=3, column=1)

    # Button for encrypt
    Button(newWindow, padx=10, pady=8, bd=12, fg="black", font=('arial', 16, 'bold'), width=8, text="Encrypt",
           bg="powder blue", command=EncryptedMsg).grid(row=4, column=1)

    # label for Decryption
    lblEncryption = Label(newWindow, font=('arial', 20, 'bold'), text="DECRYPTION", fg='blue', bd=16, anchor='w',
                          justify='center')
    lblEncryption.grid(row=5, column=1)


    # Label for Cipher Text
    lblPlainText = Label(newWindow, font=('arial', 16, 'bold'), text="Cipher Text", bd=16, anchor='w')
    lblPlainText.grid(row=6, column=0)
    lblPlainText = Entry(newWindow, font=('arial', 16, 'bold'), textvariable=CipherText, bd=10, insertwidth=4, bg="orange",
                         justify='right')
    lblPlainText.grid(row=6, column=1)

    # Label for key
    lblKey1 = Label(newWindow, font=('arial', 16, 'bold'), text="Key", bd=16, anchor='w')
    lblKey1.grid(row=7, column=0)
    lblKey1 = Entry(newWindow, font=('arial', 16, 'bold'), textvariable=Key2, bd=10, insertwidth=4, bg="orange",
                    justify='right')
    lblKey1.grid(row=7, column=1)

    # Button for decrypt
    Button(newWindow, padx=10, pady=8, bd=12, fg="black", font=('arial', 16, 'bold'), width=8,
           text="Decrypt",
           bg="powder blue", command=DecryptedMsg).grid(row=8, column=1)

    Button(newWindow, padx=10, pady=8, bd=12, fg="black", font=('arial', 16, 'bold'), width=8,
           text="Decrypt",
           bg="powder blue", command=DecryptedMsg).grid(row=5, column=1)
#..........................................CAESAR CIPHER END................................................
#..........................................ONE TIME PAD ALGORITHM OR VERNAM CIPHER.......................
def openNewWindow2():
    # Toplevel object which will
    # be treated as a new window
    newWindow = Toplevel(root)

    # sets the title of the
    # Toplevel widget
    newWindow.title("New Window")

    # sets the geometry of toplevel
    newWindow.geometry("600x600")

    def otpencrypt(text, key):
        # Initializing cipherText
        cipherText = ""
        cipher = []
        for i in range(len(key)):
            cipher.append(ord(text[i]) - ord('A') + ord(key[i]) - ord('A'))

        # If the sum is greater than 25
        for i in range(len(key)):
            if cipher[i] > 25:
                cipher[i] = cipher[i] - 26

        # Converting the no.'s into integers
        # Convert these integers to corresponding
        # characters and add them up to cipherText

        for i in range(len(key)):
            x = cipher[i] + ord('A')
            cipherText += chr(x)

        # Returning the cipherText
        return cipherText

    def otpdecrypt(s, key):
        # Initializing plain text
        plainText = ""

        # Initializing integer array of key length
        # which stores difference
        # of corresponding no.'s of
        # each character of cipherText and key

        plain = []

        # Running for loop for each character
        # subtracting and storing in the array

        for i in range(len(key)):
            plain.append(ord(s[i]) - ord('A') - (ord(key[i]) - ord('A')))

        # If the difference is less than 0
        # add 26 and store it in the array.
        for i in range(len(key)):
            if (plain[i] < 0):
                plain[i] = plain[i] + 26

        # Converting int to corresponding char
        # add them up to plainText

        for i in range(len(key)):
            x = plain[i] + ord('A')
            plainText += chr(x)

        # Returning plainText
        return plainText

    def EncryptedMsg():
        Plaintext = PlainText.get()
        key1 = Key1.get()
        encrypted_msg = otpencrypt(Plaintext.upper(), key1.upper())
        print(encrypted_msg)
        messagebox.showinfo("Encrypted message", encrypted_msg)

    def DecryptedMsg():
        Ciphertext = CipherText.get()
        key2 = Key2.get()
        decrypted_msg = otpdecrypt(Ciphertext.upper(), key2.upper())
        print(decrypted_msg)
        messagebox.showinfo("Decrypted message", decrypted_msg)



    # label for One time pad Title
    lblInfo = Label(newWindow, font=('arial', 30, 'bold'), text="ONE TIME PAD ALGORITHM", fg="green", bd=10,
                    anchor='w')
    lblInfo.grid(row=0, column=0)

    PlainText = StringVar()
    Key1 = StringVar()
    CipherText = StringVar()
    Key2 = StringVar()

    # label for Encryption
    lblEncryption = Label(newWindow, font=('arial', 20, 'bold'), text="ENCRYPTION", fg='blue', bd=16, anchor='w',
                          justify='center')
    lblEncryption.grid(row=1, column=1)

    # Label for Plain Text
    lblPlainText = Label(newWindow, font=('arial', 16, 'bold'), text="Plain Text", bd=16, anchor='w')
    lblPlainText.grid(row=2, column=0)
    lblPlainText = Entry(newWindow, font=('arial', 16, 'bold'), textvariable=PlainText, bd=10, insertwidth=4, bg="orange",
                         justify='right')
    lblPlainText.grid(row=2, column=1)

    # Label for key
    lblKey1 = Label(newWindow, font=('arial', 16, 'bold'), text="Key", bd=16, anchor='w')
    lblKey1.grid(row=3, column=0)
    lblKey1 = Entry(newWindow, font=('arial', 16, 'bold'), textvariable=Key1, bd=10, insertwidth=4, bg="orange",
                    justify='right')
    lblKey1.grid(row=3, column=1)

    # Button for encrypt
    Button(newWindow, padx=10, pady=8, bd=12, fg="black", font=('arial', 16, 'bold'), width=8,
           text="Encrypt",
           bg="powder blue", command=EncryptedMsg).grid(row=4, column=1)

    # label for Decryption
    lblEncryption = Label(newWindow, font=('arial', 20, 'bold'), text="DECRYPTION", fg='blue', bd=16, anchor='w',
                          justify='center')
    lblEncryption.grid(row=5, column=1)

    # Label for Cipher Text
    lblPlainText = Label(newWindow, font=('arial', 16, 'bold'), text="Cipher Text", bd=16, anchor='w')
    lblPlainText.grid(row=6, column=0)
    lblPlainText = Entry(newWindow, font=('arial', 16, 'bold'), textvariable=CipherText, bd=10, insertwidth=4,
                         bg="orange",
                         justify='right')
    lblPlainText.grid(row=6, column=1)

    # Label for key
    lblKey1 = Label(newWindow, font=('arial', 16, 'bold'), text="Key", bd=16, anchor='w')
    lblKey1.grid(row=7, column=0)
    lblKey1 = Entry(newWindow, font=('arial', 16, 'bold'), textvariable=Key2, bd=10, insertwidth=4, bg="orange",
                    justify='right')
    lblKey1.grid(row=7, column=1)

    # Button for decrypt
    Button(newWindow, padx=10, pady=8, bd=12, fg="black", font=('arial', 16, 'bold'), width=8,
           text="Decrypt",
           bg="powder blue", command=DecryptedMsg).grid(row=8, column=1)

    Button(newWindow, padx=10, pady=8, bd=12, fg="black", font=('arial', 16, 'bold'), width=8,
           text="Decrypt",
           bg="powder blue", command=DecryptedMsg).grid(row=5, column=1)
#..................................ONE TIME PAD END................................................................

#.................................POLY ALPHABETIC CIPHER OR VIGENERE CIPHER.....................

def openNewWindow3():
    # Toplevel object which will
    # be treated as a new window
    newWindow = Toplevel(root)

    # sets the title of the
    # Toplevel widget
    newWindow.title("New Window")

    # sets the geometry of toplevel
    newWindow.geometry("600x600")

    def polyencrypt(plaintext, key):
        key_length = len(key)

        key_as_int = [ord(i) for i in key]

        plaintext_int = [ord(i) for i in plaintext]

        ciphertext = ""

        for i in range(len(plaintext_int)):
            value = (plaintext_int[i] + key_as_int[i % key_length]) % 26

            ciphertext += chr(value + 65)

        return ciphertext

    def polydecrypt(ciphertext, key):
        key_length = len(key)

        key_as_int = [ord(i) for i in key]

        ciphertext_int = [ord(i) for i in ciphertext]

        plaintext = ""
        for i in range(len(ciphertext_int)):
            value = (ciphertext_int[i] - key_as_int[i % key_length]) % 26

            plaintext += chr(value + 65)

        return plaintext

    def EncryptedMsg():
        Plaintext = PlainText.get()
        key1 = Key1.get()
        encrypted_msg = polyencrypt(Plaintext.upper(), key1.upper())
        print(encrypted_msg)
        messagebox.showinfo("Encrypted message", encrypted_msg)

    def DecryptedMsg():
        Ciphertext = CipherText.get()
        key2 = Key2.get()
        decrypted_msg = polydecrypt(Ciphertext.upper(), key2.upper())
        print(decrypted_msg)
        messagebox.showinfo("Decrypted message", decrypted_msg)

    # label for Poly alphabetic Title
    lblInfo = Label(newWindow, font=('arial', 30, 'bold'), text="POLY ALPHABETIC ALGORITHM", fg="green", bd=10,
                    anchor='w')
    lblInfo.grid(row=0, column=0)

    PlainText = StringVar()
    Key1 = StringVar()
    CipherText = StringVar()
    Key2 = StringVar()

    # label for Encryption
    lblEncryption = Label(newWindow, font=('arial', 20, 'bold'), text="ENCRYPTION", fg='blue', bd=16, anchor='w',
                          justify='center')
    lblEncryption.grid(row=1, column=1)

    # Label for Plain Text
    lblPlainText = Label(newWindow, font=('arial', 16, 'bold'), text="Plain Text", bd=16, anchor='w')
    lblPlainText.grid(row=2, column=0)
    lblPlainText = Entry(newWindow, font=('arial', 16, 'bold'), textvariable=PlainText, bd=10, insertwidth=4, bg="orange",
                         justify='right')
    lblPlainText.grid(row=2, column=1)

    # Label for key
    lblKey1 = Label(newWindow, font=('arial', 16, 'bold'), text="Key", bd=16, anchor='w')
    lblKey1.grid(row=3, column=0)
    lblKey1 = Entry(newWindow, font=('arial', 16, 'bold'), textvariable=Key1, bd=10, insertwidth=4, bg="orange",
                    justify='right')
    lblKey1.grid(row=3, column=1)

    # Button for encrypt
    Button(newWindow, padx=10, pady=8, bd=12, fg="black", font=('arial', 16, 'bold'), width=8,
           text="Encrypt",
           bg="powder blue", command=EncryptedMsg).grid(row=4, column=1)

    # label for Decryption
    lblEncryption = Label(newWindow, font=('arial', 20, 'bold'), text="DECRYPTION", fg='blue', bd=16, anchor='w',
                          justify='center')
    lblEncryption.grid(row=5, column=1)

    # Label for Cipher Text
    lblPlainText = Label(newWindow, font=('arial', 16, 'bold'), text="Cipher Text", bd=16, anchor='w')
    lblPlainText.grid(row=6, column=0)
    lblPlainText = Entry(newWindow, font=('arial', 16, 'bold'), textvariable=CipherText, bd=10, insertwidth=4,
                         bg="orange",
                         justify='right')
    lblPlainText.grid(row=6, column=1)

    # Label for key
    lblKey1 = Label(newWindow, font=('arial', 16, 'bold'), text="Key", bd=16, anchor='w')
    lblKey1.grid(row=7, column=0)
    lblKey1 = Entry(newWindow, font=('arial', 16, 'bold'), textvariable=Key2, bd=10, insertwidth=4, bg="orange",
                    justify='right')
    lblKey1.grid(row=7, column=1)

    # Button for decrypt
    Button(newWindow, padx=10, pady=8, bd=12, fg="black", font=('arial', 16, 'bold'), width=8,
           text="Decrypt",
           bg="powder blue", command=DecryptedMsg).grid(row=8, column=1)
           
    Button(newWindow, padx=10, pady=8, bd=12, fg="black", font=('arial', 16, 'bold'), width=8,
           text="Decrypt",
           bg="powder blue", command=DecryptedMsg).grid(row=5, column=1)

root = Tk()
root.geometry('1600x800+0+0')
root.title("SUBSTITUITION ALGORITHM")

Tops = Frame(root, width=1600, height=800)
Tops.pack(side=TOP)

#Label for Title
lblInfo = Label(Tops,font=('arial',40,'bold'),text = "SUBSTITUITION TECHNIQUES IN CRYPTOGRAPHY",fg = "black",bd=10,anchor='w')
lblInfo.grid(row=0,column=0)

Caesar = Button(Tops, padx=25, pady=8, bd=12, fg="brown", font=('arial', 16, 'bold'), width=8, text="Caesar Cipher", bg="yellow", command=openNewWindow1)
Caesar.grid(row=1, column=0)
OneTimePad = Button(Tops, padx=25, pady=8, bd=12, fg="brown", font=('arial', 16, 'bold'), width=8, text="One Time Pad", bg="yellow", command=openNewWindow2)
OneTimePad.grid(row=2, column=0)
PolyAlphabetic = Button(Tops, padx=25, pady=8, bd=12, fg="brown", font=('arial', 16, 'bold'), width=8, text="Poly Alphabetic", bg="yellow", command=openNewWindow3)
PolyAlphabetic.grid(row=3, column=0)

root.mainloop()
