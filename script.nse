description = "Custom NSE Script for results"
categories = {"default"}
action = function (host, port)
   os.execute("g++ -o temp results/result.cpp -lpcap -std=c++11")
   os.execute("sleep 5")
   os.execute("./temp")
end
portrule = function (host, port)
  return true
end
