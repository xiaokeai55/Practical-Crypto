# JMessage Overview

This repository contains code and specifications for the JMessage system.

See the following resources:

* [JMessage Specification](specification.md)
* [How to run the JMessage server locally](running_server.md)

In addition, you will find code for the server and a skeleton of the unfinished Golang client.

## Problem 2: Attacking a Messaging Client

To automatically decrypt the intercepted message, follow steps below:

1. Run the jmessage server, and create dummy users with "-t" option if it is the first time you run the server.
    * USAGE: python3 jmessage_server.py -t
2. Open a terminal and run client as alice in headless mode.
    * USAGE: $ go run jmessage_client_unfinished.go -headless
3. Open a new terminal and run client as charlie. 
    * USAGE: $ go run jmessage_client_unfinished.go -username charlie -password ghi
4. Send any message as charlie to alice. The message will be automatically intercepted and stored into file "ciphertext.txt".
    * USAGE: $ send alice
5. Open another new terminal and run the client in auto attack mode. The message will be decrypted byte by byte. Once the decryption is finished, a "Decrypt success" message will be printed out in the terminal.
    * USAGE: $ go run jmessage_client_unfinished.go -attack ciphertext.txt -victim alice
