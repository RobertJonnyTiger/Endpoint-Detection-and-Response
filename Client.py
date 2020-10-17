#!/usr/bin/python3
""" Description: This is the client's code. """
import socket
import urllib.request
from os import path, remove
from platform import system
from subprocess import check_output, run
from threading import Thread
from time import sleep
from bs4 import BeautifulSoup
from scapy.all import *

TAB_1 = '\t'
TAB_2 = '\t\t'

# Gets the running OS as a variable:
runningOS = system()

HOST = '10.100.102.67'  # Server IP.
PORT = 1111  # Server's listening port.

restrictedSitesList = []


# main:
# Creats a socket object.
# Connects to server and prints the welcome message.


def main():
    global clientSocket
    # Client's Socket Object:
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print('Trying to connect to the server...')
    try:
        clientSocket.connect((HOST, PORT))  # Connects to the server's socket.
        print(f'[INFO] You are connected to: {HOST} in port: {PORT}.')
        welcomeMessage = clientSocket.recv(1024)  # Receives welcome message.
        print(welcomeMessage.decode())
    except socket.error as error:
        exit(
            f'[ERROR] Connecting to the server failed:\n\033[31m{error}\033[0m')


# MITM:
# Checks for duplications in ARP table in both Linux and Windows.
# Iterates through the MAC addresses in the ARP table, adding them to a list.
# If a duplication occurs - the value of the MAC in the dictionary will rise by 1.
# For every MAC key that has a value of more than 1, it will send a warning message to the server.
# The scan happens every sleep(x seconds) - modify to your liking.
def MITM():
    while True:
        macList = []
        macDict = {}
        if runningOS == "Windows":
            ARPmacs = check_output("arp -a", shell=True).decode()

            for line in ARPmacs.splitlines():
                if "dynamic" in line:
                    macList.append(line[24:41])

            for MAC in macList:
                if MAC in macDict:
                    macDict[MAC] = macDict[MAC] + 1
                else:
                    macDict[MAC] = 1

            for MAC, value in macDict.items():
                if value >= 2:
                    clientSocket.send(
                        f'[WARNING] Found MAC address duplication. Possible Man in the Middle Attack!\nCheck this MAC: {MAC}\n\n'.encode())

        elif runningOS == "Linux":
            ARPmacs = check_output(
                "arp | awk '{print $3}' | grep -v HW | grep -v eth0", shell=True).decode()
            for line in ARPmacs.splitlines():
                macList.append(line)

            for MAC in macList:
                if MAC in macDict:
                    macDict[MAC] = macDict[MAC] + 1
                else:
                    macDict[MAC] = 1
            for MAC, value in macDict.items():
                if value >= 2:
                    clientSocket.send(
                        f'[WARNING]Found MAC address duplication. Possible Man in the Middle Attack!\nCheck this MAC: {MAC}\n\n'.encode())
        sleep(15)


# restricted_Sites_List_Maker:
# Creats a list of website names that will be used as arguments for the DNS sniffer.
# The function gets the websites from the restricted_sites.html webpage running on the apache2 server.
# Only the server adming will have access to the html where the blacklist is stored.
# The update happens every sleep(x seconds) - modify to your liking.
def restricted_Sites_List_Maker():
    while True:
        # Restricted Websites webpage:
        restrictedWebsites = f"http://{HOST}/restricted_sites.html"

        HTMLrestrictedWebsites = urllib.request.urlopen(
            restrictedWebsites).read()
        soup = BeautifulSoup(HTMLrestrictedWebsites, features="lxml")

        textRestictedWebsites = soup.body.get_text()  # Gets text.

        # Breaks into lines and remove leading and trailing space on each:
        lines = (line.strip() for line in textRestictedWebsites.splitlines())

        # Breaks multi-headlines into a line each:
        chunks = (phrase.strip()
                  for line in lines for phrase in line.split("  "))

        # Drops blank lines. Final result:
        textRestictedWebsites = '\n'.join(chunk for chunk in chunks if chunk)

        # Creates \ Overwrites \ the list of sites to a txt file from the html page.
        if runningOS == "Windows":
            if path.exists("Restricted_Sites.txt"):
                remove("Restricted_Sites.txt")

            with open("Restricted_Sites.txt", "w") as restrictedSitesFile:
                restrictedSitesFile.write(textRestictedWebsites)
                # Makes the file hidden.
                run("attrib +h Restricted_Sites.txt", shell=True)

            # Appends the site to the restrictedSitesList:
            with open("Restricted_Sites.txt", "r") as f:
                for siteLine in f.readlines():
                    restrictedSitesList.append(siteLine.strip())

        elif runningOS == "Linux":
            with open(".Restricted_Sites.txt", "w") as restrictedSitesFile:
                restrictedSitesFile.write(textRestictedWebsites)

            # Appends the site to the restrictedSitesList
            with open(".Restricted_Sites.txt", "r") as f:
                for siteLine in f.readlines():
                    restrictedSitesList.append(siteLine.strip())
        sleep(60)

# findDNS:
# Sniffs DNS quearys of the client.
# Gets only the name of the website from the queary. Setting it to url variable.
# if the name of the site from the restrictedSitesList found in the current sniffed url variable - sends an alert to the server.


def findDNS(pkt):
    if pkt.haslayer(DNS):
        if "Qry" in pkt.summary():  # Only quearys.
            # Gets only the name of the website from the queary:
            url = pkt.summary().split('\"')[-2].replace("", "")[2:-2]
            for site in restrictedSitesList:
                if site in url:
                    clientSocket.send(
                        f'[ALERT] Entered a restricted website:\n{site}\n\n'.encode())


if __name__ == '__main__':
    main()
    Thread(target=restricted_Sites_List_Maker).start()
    Thread(target=MITM).start()
    Thread(target=sniff(prn=findDNS)).start()
