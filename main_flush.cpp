#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <vector>
#include <set>
#include <algorithm>

typedef std::map <long int, long int> AddressMap; // the key of map is the start of the address range and the value is the end of the range

// inputs
int numFlushed = 16;
int frame = 1e6;
std::vector<std::string> buffer;
bool readFromBuffer = false;

long int num_leakages = 0;

long long int getTimeStamp(const std::string& str) {
    std::size_t firstColon = str.find(':');
    long long int time = 0;
    try {
        time = std::stoi(str.substr(0, firstColon));
    } catch (const std::invalid_argument &e) {
        return -1;
    }
    return time;
}

class Victim {
public:
    Victim() {
        set = 0;
        way = 0;
        address = 0;
        time = 0;
        branch = "";
    }
    unsigned int set;
    unsigned int way;
    long int address;
    long long int time;
    std::string branch;
};

//This function checks if a sufficient number of cache lines are flushed 
//for a successful attack
bool checkEventOne(AddressMap & mapFlushedAddresses) {
    int count = 0;
    for (const auto& kv : mapFlushedAddresses) {
        count++;
        if (count >= numFlushed) {
            return true;
        }
    }
    return false;
}

void printMap(AddressMap & mapFlushedAddresses){
    std::cout << "------ Flushed Addresses --------" << std::endl;
    for (auto & itr : mapFlushedAddresses){
        std::cout << "Start: " << itr.first << ", End: " << itr.second << std::endl;
    }
    std::cout << "--------------------------------" << std::endl;
}

void customMapClear(AddressMap & mapFlushedAddresses){
	//Do nothing 
	//Note: Context switches are unlikely to interfere with the flushed cache lines
	//		In spite of Prime+Probe which context switch can distrupt the attack
}

std::string findBranchSquash(const std::string& str) {
    std::size_t addrColonPos = str.find("addr: ");
    std::size_t commaPos = str.find(',');
    if (addrColonPos != std::string::npos) {
        std::size_t pos = addrColonPos + 6;
        std::string addrStr = str.substr(pos, commaPos - pos);
        return addrStr;
    }
    return "";
}

bool isBranchLookup(const std::string& str){
    if (str.find("system.cpu.branchPred") != std::string::npos && str.find("Lookup") != std::string::npos){
        return true;
    }
    return false;
}

std::string returnBranchLookup(const std::string& str){
    std::size_t addrColonPos = str.find("branch: ");
    std::size_t commaPos = str.find(';');
    if (addrColonPos != std::string::npos){
        std::size_t pos = addrColonPos + 8;
        std::string addrStr = str.substr(pos, commaPos - pos);
        return addrStr;
    }
    return "";
}

void AddressFind(const std::string& str, AddressMap & mapFlushedAddresses){
    std::size_t openBracketPos = str.find('[');
    std::size_t closeBracketPos = str.find(']');
    if (openBracketPos != std::string::npos && closeBracketPos != std::string::npos){
        std::size_t pos = openBracketPos + 1;
        std::size_t length = closeBracketPos - pos;
        std::string addr_range = str.substr(pos, length);

        pos = addr_range.find(':');
        std::string start_str = addr_range.substr(0, pos);
        std::string end_str = addr_range.substr(pos + 1);

        long int range_start;
        std::istringstream iss1(start_str);
        iss1 >> std::hex >> range_start;
        long int range_end;
        std::istringstream iss2(end_str);
        iss2 >> std::hex >> range_end;

        if(range_end == range_start)
            range_end = range_start + 64; //in gem5 range_start and range_end are the same but the size of each block is 64
                                          //this is the case for CLFLUSH (cache CleanInvalidReq)
        auto itr = mapFlushedAddresses.find(range_start);
        if (itr == mapFlushedAddresses.end()){
            mapFlushedAddresses.insert(std::pair <long int, long int>(range_start, range_end));
        }
    }
}

//This function checks if a cache flush has happened
bool checkCleanInvalidAccess(const std::string& str, AddressMap & mapFlushedAddresses){
    if (str.find("CleanInvalidReq") != std::string::npos && str.find("system.cpu.dcache") != std::string::npos){
        AddressFind(str, mapFlushedAddresses);
        return true;
    }
    return false;
}

bool checkMissAccess(const std::string& str, AddressMap & mapFlushedAddresses) {
    if (str.find("miss") != std::string::npos && str.find("system.cpu.dcache") != std::string::npos
        && (str.find("ReadReq") || str.find("WriteReq"))) {
        AddressFind(str, mapFlushedAddresses);
        return true;
    }
    return false;
}

std::string getNextLine(std::ifstream& file, std::string str = "") {
    if (!str.empty())
        return str;
    std::string out = "";
    if (readFromBuffer) {
        if (!buffer.empty()) {
            out = buffer[0];
            buffer.erase(buffer.begin());
            return out;
        } else {
            readFromBuffer = false;
            if (std::getline(file, out))
                return out;
            return "-";
        }
    } else {
        if (std::getline(file, out))
            return out;
        return "-";
    }
}

//This function checks if a potential victim accesses one of the flushed cache lines
//This function runs only if event one(a sufficient number of cache lines are flushed) has happened 
bool checkSecondEvent(std::ifstream& file, std::string& str,
                              AddressMap & mapFlushedAddresses,
                              std::vector<Victim>& output) {
    AddressMap newMapFlushedAddresses;
    bool squashSeen = false;
    int countMiss = 0;
    int allMisses = 0;
    bool isAttacker = false;//this is the alert
    std::string tempStr = str;
    long long int t1 = getTimeStamp(str);
    std::set<std::string> LookedUpBranches;
    long long int miss_time;
    while (true) {
        std::string currentStr = getNextLine(file, tempStr);
        str = currentStr;
        tempStr = "";
        if (currentStr == "-")
            break;
        if (getTimeStamp(currentStr) - t1 > frame)      // this frame is finished
            break;
        //Make sure to check for misses and squash after a branch lookup
        if (isBranchLookup(currentStr)){
            LookedUpBranches.insert(returnBranchLookup(currentStr));
        }
        if (checkMissAccess(currentStr, newMapFlushedAddresses) && !LookedUpBranches.empty()) {
            allMisses ++;
            miss_time = getTimeStamp(currentStr);
        }
        if (currentStr.find("Squash") != std::string::npos) {
            std::string BR = findBranchSquash(currentStr);
            if (!newMapFlushedAddresses.empty()) {
				//only the first squash matters that there has been a miss in its speculation window
                auto BRfound = LookedUpBranches.find(BR);
                if (!squashSeen && BRfound != LookedUpBranches.end()) {//checking if the branch of this squash is among the looked up branches
                    squashSeen = true;
                    countMiss = allMisses;

                    //pruning the newMapFlushedAddresses: Only keeping the locations that overlap with newMapFlushedAddresses
                    AddressMap tempMapFlushedAddresses = newMapFlushedAddresses; //taking a checkpoint before pruning
                    for (auto & itr : newMapFlushedAddresses)
                    {
                        bool overlaps = false;
                        for (auto & itr2 : mapFlushedAddresses){
                            if (itr.first >= itr2.first && itr.first <= itr2.second){
                                overlaps = true;
                            }
                        }

                        if (!overlaps){
                            newMapFlushedAddresses.erase(itr.first);
                        }
                    }

                    if (newMapFlushedAddresses.size() == 1){//only one location should have been accessed
                        for (auto & itr : newMapFlushedAddresses){
                            auto flushed_accessed_address = itr.first;
                            isAttacker = true;
                            Victim victim;
                            victim.address = flushed_accessed_address;
                            victim.time = miss_time;
                            victim.branch = BR;
                            output.push_back(victim);
                        }
                    }
                    newMapFlushedAddresses = tempMapFlushedAddresses; //making sure we restore newMapFlushedAddresses after the pruning
                }
            } 
            else {    // only notice to first Squash
                LookedUpBranches.erase(BR);
                // check if # of miss accesses has increased or not. if yes -> no output(unsuccessful attack)
                if (allMisses > countMiss) {
                    isAttacker = false;
                    output.clear();
                }
            }
        }
    }
    return isAttacker;
}


int main(int argc, char** argv) {
    std::string file_name = argv[1];
    std::ifstream file(file_name);
    std::cout << "The input report file: " << file_name << std::endl;

    std::string str_num_flushed = argv[2];
    numFlushed = std::stoi(str_num_flushed);
    std::cout << "Threshold for the number of flushed locations: " << numFlushed << std::endl;

    std::string frame_str = argv[3];
    frame = std::stoi(frame_str);
    std::cout << "Frame size: " << frame << std::endl;

    std::string str;
    long long int currentFrame = 0;
    AddressMap mapFlushedAddresses;

    int frame_count = 0;

    while (true)
    {
        str = getNextLine(file);
        if (str == "-")
            break;
        long long int time = getTimeStamp(str);
        if (time < 0)
            continue;

        if (time / frame > currentFrame) {
            frame_count++;
            
            long long int oldCurrentFrame = currentFrame;
            currentFrame = time / frame;
            if (checkEventOne(mapFlushedAddresses)) {
                std::vector<Victim> output;
                if (checkSecondEvent(file, str, mapFlushedAddresses, output)) {
					//This frame is an attacker. resetting the mapFlushedAddresses 
					num_leakages++;
                    customMapClear(mapFlushedAddresses);
                    buffer.clear();
                } else {
					//This frame is not an attacker. checking for event one in next frame
                    customMapClear(mapFlushedAddresses);
                }
                currentFrame = getTimeStamp(str) / frame;

            } else {
                // resetting the mapFlushedAddresses
                customMapClear(mapFlushedAddresses);
                // analyze new frame just for event one
                checkCleanInvalidAccess(str, mapFlushedAddresses);
            }

        } else {
            // still search and analyze event one in current frame
            checkCleanInvalidAccess(str, mapFlushedAddresses);
        }
    }

    std::cout << "==> Number of leakages: " << num_leakages << std::endl;
    return 0;
}
