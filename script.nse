os.execute("g++ -o temp src/tcp_result.cpp -lpcap")
os.execute("sleep 2")
os.execute("./temp")
