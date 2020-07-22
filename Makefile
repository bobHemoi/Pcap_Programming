all		:	pcap_programming

pcap_programming : main.o 
		g++ -o pcap_programming main.o -lpcap

main.o	:	main.cpp 
		g++ -c -o main.o main.cpp -lpcap


clean	:
		rm -f pcap_programming *.o