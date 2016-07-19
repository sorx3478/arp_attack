packet_capture: main.o
	g++ -o arp_attack main.o -lpcap

main.o: main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -f ./*.o
	rm -f ./arp_attack
