gcc example3.c -o example3 -Wall -lpcap $(pkg-config ntoh --cflags --libs);
sudo ./example3 -i eth0 -F "tcp";