description = "Custom NSE Script for TCP results"
categories = {"default"}
action = function ()
   os.execute("g++ -o temp src/result.cpp -lpcap")
   os.execute("sleep 2")
   os.execute("./temp")
end
portrule = function ()
  return true
end
