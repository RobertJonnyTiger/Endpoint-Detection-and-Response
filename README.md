# Endpoint-Detection-and-Response
Python EDR system Example (server and client-side)
A minimal example of how an EDR system would work in Python3.8. The project contains the server-side code and the client-side code.
Server-side code will run on a server while the client-side code will run on many different clients. The EDR analyzes the client's web traffic and alerts the server if a client entered a restricted website. The restricted websites are pulled from a database stored in the Apache webserver every 60 seconds (Changeable in the code). The server updates the restricted websites list and the clients as well every 60 seconds.
Meanwhile, the client-side code monitors the ARP table to check if there is a possible Man-in-the-middle attack. If such an attack occurs it will immediately send an alert to the server with the suspected client's IP address that being a possible victim to an attack.

# Code Workflow
1. Runs a listening server on a Linux machine.
2. Clients connecting to the server and sends data to the server.
3. Server logs relevant data to log files.
4. Meanwhile, the server monitors if a client has been disconnected and alerts to the screen.

Please add credits if you use any of the code :)
