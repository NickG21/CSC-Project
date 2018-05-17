# Net Navigator
The Net Navigator is a program that allows the user to view the nearby devices and their components without being connected to the same network. 
# Dependencies
* Network Card w/ monitor mode
* Python Scapy
* BeautifulSoup4
* Aircrack-ng Suite
# How to Run Net Navigator
To run the program, you need to initially set your network card to monitor mode. If you want to channel hop, we suggest that you run airodump-ng <iface>.
After your network card is in monitor mode, simply run the <b>main.py</b> file. (you might need to run as root)
```bash
sudo main.py
```
