# PWM
A very little Password Manager written in C for Linux Command Line

This project was developed as a final semester project of Security in Information Systems of Mathematical Reserch Center in Mexico, was written in language C pure with the implementation of the algorithm AES256 for ciphering sensitive information and the SQLite3 Technology, the libraries in this project was: kokke/tiny-AES-c, a little library for the AES implementation and  littlstar/b64.c, another library to format ciphered information to save it in a data base with the SQLite3 engine.

This software comes as it is with absolutely no warranty, feel free to modify the code into your personal preferences.

You need to compile the program in order to use it using gcc on the command line in linux.

    gcc main.c sqlite3.c aes256.c encode.c decode.c -o <output_name> -ldl -lpthread

If you have any doubts send me a question and i will try to answer it as soon as posible.
 
