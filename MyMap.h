#include <bits/stdc++.h>
#include "FS.h"
#include "SPIFFS.h"
using namespace std;

typedef unordered_map<string, int> aMap;
//const char* fileName = "/MapData.txt";

class MyMap {
public:
  MyMap(char* theFileName){
    fileName = theFileName;
  }
  void storeMap(char* timeDate) {
    aMap::iterator p;
    //cout << timeDate << endl;
    // for (p = theMap.begin(); p != theMap.end(); p++) {
    //   cout << "(" << p->first << "; " << p->second << ")" << endl;
    //   //  p++ is done in the erase(p) automatically!
    //   //theMap.erase(p);
    // }
    if (openFile()) {
      //Serial.println("Writing to file");
      //int m = 
      file.print(timeDate);
      file.println(",,,,,");
      //cout << "bytes written :" << m << endl;
      char message[32];
      for (p = theMap.begin(); p != theMap.end(); p++) {
        //cout << "," << p->first << "," << p->second  << endl;
        sprintf(message, ",%s,%03d", p->first.c_str(), p->second);
        int n = file.println(message);
        //cout << "bytes written :" << n << endl;
        //Serial.println(message);
      }
      file.close();
    } else {
      //cout << "File creation/Open error";
    }
    theMap.erase(theMap.begin(), theMap.end());
  }

  void addToMap(string theString) {
    //aMap::const_iterator found = theMap.find(theString);
    // if (found == theMap.end()) {
    //   cout << "new element:" << theString << endl;
    // }
    theMap[theString]++;
  }

  int size() {
    return theMap.size();
  }

private:
  char* fileName;
  aMap theMap;
  File file;
  bool openFile() {
    bool retval = false;
    if (!SPIFFS.begin(true)) {
      //Serial.println("SPIFFS Mount Failed");
      return false;
    }
    if (SPIFFS.exists(fileName)) {
      //append
      //Serial.println("Open for append");
      retval = file = SPIFFS.open(fileName, FILE_APPEND);
    } else {
      //write
      //Serial.println("New File");
      retval = file = SPIFFS.open(fileName, FILE_WRITE);
      file.println("Date,Dest_type,Destination,Sender_type,Sender,SSID,Count");
    }
    //Serial.println("File Opened");
    return retval;
  }
};