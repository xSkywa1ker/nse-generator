os.execute("g++ -o test src/tcp_result.cpp -lpcap")
os.execute("sleep 5")
os.execute("./test")
