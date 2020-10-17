#!/usr/bin/python3
'''
==================================================================================================================================
Course:
   Cyber Security, May, 2020
Project Name:
   #3 - Python - Endpoint Detection and Response.
Objective:
   Create an Endpoint Detection and Response System (EDR)
Student Name:
   Robert Jonny Tiger.
==================================================================================================================================
'''
import socket
import urllib.request
from pathlib import Path
from subprocess import check_output, run
from threading import Thread
from time import sleep

TAB_1 = '\t'
TAB_2 = '\t\t'

PROJECTPATH = Path(__file__).resolve().parent
HOST = '0.0.0.0'
PORT = 1111

# Socket object.
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

connectionsCount = 0  # How many clients are connected to the server.
activeAddressesList = []  # List of connected addresses.
openClientSocketsList = []  # List of open socket connections.

# apache2start:
# checks if apache2 is installed. if not - exits the code with a message.
# Starts apache2 server.
# Copies the local restriced_sites.html to the actual html folder in /var/www/html where apache2 is running from.
# Server admin edits the file inside the /var/www/html to update the restricted sites list.


def apache2Start():
    apache2InstallStatus = check_output(
        "dpkg --get-selections | grep apache2-bin | awk '{print $2}'", shell=True)
    if apache2InstallStatus:
        run("service apache2 start", shell=True)
        try:
            response = urllib.request.urlopen(
                'http://0.0.0.0/restricted_sites.html')
        except:
            while response.status != 200:
                run('service apache2 restart', shell=True)
                sleep(5)
    else:
        exit('[ERROR] \033[31mApache2 service is not installed, make sure to install Apache2 and run the server again\033[0m')
    print('[INFO] Apache2 Server Started (http://localhost:80)')
    print('[INFO] restricted_sites.html copied to /var/www/html\nEdit the file inside /var/www/html to add or remove restricted sites for clients.')


# main:
# Binds socket to ((HOST, PORT)), listening to connections, accepting new connections, sets a format for connName.
# Sends welcome message to new clients, appends new client's socket objects and connName to the lists.
# Starts 2 threads: One for handling clients and the other for checking connections with clients.
def main():
    try:
        serverSocket.bind((HOST, PORT))  # Bind the socket.
        print(f'[INFO]Server address binded to self ({HOST})')
    except socket.error as error:
        exit(
            f'[ERROR] Error in Binding the Server:\n\033[31m{error}\033[0m')
    print(
        f'[INFO] Listening on port {PORT}... (Waiting for connections)')
    serverSocket.listen(50)
    for clientSocket in openClientSocketsList:
        # Closes all preavious connections if Server.py restarted:
        clientSocket.close()
        # Deletes all previous open client sockets and active addresses from the lists:
        del openClientSocketsList[:], activeAddressesList[:]

    while True:
        try:
            # Accepts connections:
            conn, (address, port) = serverSocket.accept()
            # Appends the client's socket to the list:
            openClientSocketsList.append(conn)
            # Set a format for the connName using client's address and port:
            connName = '{}:{}'.format(address, port)
            print(f'[INFO] {connName} Connected!')
            welcomeMessage = f'Successfully connected to EDR Server at {HOST}:{PORT}'
            # Sends welcome message to the client:
            conn.send(welcomeMessage.encode())
            global connectionsCount
            connectionsCount += 1  # Adding +1 to the connections count.
            # Appends the new address to the activeAddressesList:
            activeAddressesList.append(connName)
            # Prints current connections count:
            print(
                f'[INFO] Number of Active Connections: {connectionsCount}')
            # Starts a new thread to handle each client (args are the connection and formatted connection name):
            Thread(target=handleClient, args=(conn, connName)).start()
            # Starts a checkConnections thread:
            Thread(target=checkConnections).start()
        except socket.error as acceptError:
            print(
                f'[ERROR] Accepting Connection from: {conn.getpeername()}:\n\033[31m{acceptError}\033[0m')
            continue


# handleClient(conn, connName):
# Main function to recieve data from all clients.
# Handles client connections using args from main.
# If data has "MAC" in it, logs the data to 'MitM Logger.log'
# If data has "restricted" in it, logs the data to 'Restricted Sites Logger.log'
def handleClient(conn, connName):
    while True:
        try:
            data = conn.recv(4096).decode()
            if "MAC" in data:
                # Timestamp for the log file:
                timestamp = check_output(
                    "date -u +'%d/%m/%Y %H:%M'", shell=True).decode().rstrip()
                print(
                    '[WARNING] Possible Man in the Middle attack. Check MitM Logger.log')
                with open(f"{PROJECTPATH}/MitM Logger.log", "a+") as MitMLog:
                    MitMLog.write(
                        f"[{timestamp}]{TAB_1}[{connName}]:\n{data}")  # Logs the MitM attack from the client to 'MitM Logger.log'

            if "restricted" in data:
                # Timestamp for the log file:
                timestamp = check_output(
                    "date -u +'%d/%m/%Y %H:%M'", shell=True).decode().rstrip()
                print(
                    f'[ALERT] Someone entered to a restricted site. Check Restricted Sites Logger.log')
                with open(f'{PROJECTPATH}/Restricted Sites Logger.log', 'a+') as restrictedLog:
                    restrictedLog.write(
                        f"[{timestamp}]{TAB_1}[{connName}]:\n{data}")  # Logs the restricted site from the client to 'Restricted Sites Logger.log'
        except:
            pass


# noinspection PyBroadException
# checkConnections:
# Checks what clients are alive by iterating through every client socket object and trying to send a whitespace string.
# If an exception occurs, it means that the client is dead.
# Deletes the client socket object and address from the lists and decreasing 1 from connections count.
# This check happens every 30 seconds.
def checkConnections():
    while True:
        global connectionsCount
        if len(openClientSocketsList) != 0:
            for x, currentSocket in enumerate(openClientSocketsList):
                try:
                    # Send a whitespace to every socket in the list:
                    pingToClientMessage = ' '
                    currentSocket.send(pingToClientMessage.encode())
                except:
                    print(f'[INFO] Client {x} Disconnected!')
                    # Deletes the client socket and address from the lists:
                    del openClientSocketsList[x], activeAddressesList[x]
                    connectionsCount -= 1
                    if connectionsCount == 0:  # If no connections left:
                        print(f'[INFO] No active connections left.')
                    else:  # If there are still connections left:
                        print(
                            f'[INFO] Number of Active Connections: {connectionsCount}')
                        print('[INFO] Active addresses connected:')
                        # Prints a list of the current open connections:
                        for index, value in enumerate(activeAddressesList):
                            print(f'{TAB_1}{index}.{TAB_1}{value}')
                    continue
        sleep(30)


# Start of the Script:
if __name__ == '__main__':
    apache2Start()
    main()
