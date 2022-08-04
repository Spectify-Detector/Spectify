#include <iostream>
#include <assert.h>
#include <iomanip>
#include <fstream>
#include <map>
#include <vector>
#include <set>
#include <queue>
#include <algorithm>
#include <random>
#include <regex>

typedef std::map <unsigned int, std::vector<std::pair<long long int, unsigned int>>> SetTimeWay;

// inputs
int set = 2;
int way = 2;
int frame = 1e6;
long int initial_tick = 0;

//cpu name in gem5 stat
std::string cpu_name;

//This variable specifies the percentage of primed cache sets are touched during context switch
int mapClearPercentage;

//number of frames to dump stats frequently
int stat_interval;

//statistics
long int frame_count;
long int num_leakages;
long int event_one_count;//Number of event one (a sufficient number of cache sets are primed)
long double avg_primed;
long int num_speculative_accessed_not_squashed;
long int num_squahed_speculative_accesses_not_primed;
long int num_squahed_speculative_accesses_multVictimAccesses;
long int num_multi_interfering_leakages;

std::vector<std::string> buffer;
bool readFromBuffer = false;
std::queue<std::string> Queue;

SetTimeWay mergeMapPrimedCacheSet;

void init_stats(){
    frame_count = 0;
    num_leakages = 0;
    event_one_count = 0;
    avg_primed = 0;
    num_speculative_accessed_not_squashed = 0;
    num_squahed_speculative_accesses_not_primed = 0;
    num_squahed_speculative_accesses_multVictimAccesses = 0;
    num_multi_interfering_leakages = 0;
}

void dump_stats(){
    std::cout << "==============================( Statistics )==============================" << std::endl;
    std::cout << std::left;
    std::cout << std::setw(60) << "Number of frames" << frame_count << std::endl;
    std::cout << std::setw(60) << "Number of event one" << event_one_count << std::endl;
    std::cout << std::setw(60) << "Average primed cache sets" << std::setw(10) << avg_primed << std::endl;
    std::cout << std::setw(60) << "Number of speculative access but not squahed" << num_speculative_accessed_not_squashed << std::endl;
    std::cout << std::setw(60) << "Number of squahed speculative access but not primed" << num_squahed_speculative_accesses_not_primed << std::endl;
    std::cout << std::setw(60) << "Number of squahed speculative access but multi accesses" << num_squahed_speculative_accesses_multVictimAccesses << std::endl;
    std::cout << std::setw(60) << "Number of multiple interfering leakages in one frame" << num_multi_interfering_leakages << std::endl;
    std::cout << std::setw(60) << "Number of leakages" << num_leakages << std::endl;
}

long long int getTimeStamp(const std::string& str) {
    std::size_t firstColon = str.find(':');
    long long int time = 0;
    try {
        time = std::stol(str.substr(0, firstColon));
    } catch (const std::invalid_argument &e) {
        return -1;
    }
    return time - initial_tick;
}

class Victim {
public:
    Victim() {
        set = 0;
        way = 0;
        time = 0;
        branch = "";
    }
    unsigned int set;
    unsigned int way;
    long long int time;
    std::string branch;
};

//Checking for event one (a sufficient number of cache sets are primed)
bool checkEventOne(SetTimeWay & mapPrimedCacheSet) {
    int count = 0;
    std::set<unsigned int> way_set; //a set of cache ways accessed

    for (const auto& kv : mapPrimedCacheSet) {
        way_set.clear();
        for (auto p = kv.second.begin(); p != kv.second.end(); p++)
            way_set.insert((*p).second);

        if (way_set.size() >= way) {//All cache ways should be present in the accessed list
            count += 1;
        }
    }

    if (count >= set) 
        return true;
    else
        return false;
}

static int processing_frame_for_avg = 0;
void averagePrimed(SetTimeWay & mapPrimedCacheSet, long int F){
    int count = 0;
    assert(processing_frame_for_avg == F);//averages should be taken for all frames and in order
    processing_frame_for_avg++;

    std::set<unsigned int> way_set; //a set of cache ways accessed
    for (const auto& kv : mapPrimedCacheSet) {
        way_set.clear();
        for (auto p = kv.second.begin(); p != kv.second.end(); p++)
            way_set.insert((*p).second);

        if (way_set.size() >= way) {//All cache ways should be present in the accessed list
            count += 1;
        }
    }

    avg_primed = ((double)count + (avg_primed * ((double)F))) / ((double)F+1);
}

void printMap(SetTimeWay & mapPrimedCacheSet){
    std::cout << "------ Primed Cache Sets --------" << std::endl;
    std::cout << "{";

    std::set<unsigned int> way_set; //a set of cache ways accessed
    bool found = false;

    for (auto & itr : mapPrimedCacheSet){
        way_set.clear();

        for (auto p = itr.second.begin(); p != itr.second.end(); p++)
            way_set.insert((*p).second);

        if (way_set.size() >= way){
            if (!found)//first primed set
                std::cout << itr.first;
            else   
                std::cout << ", " << itr.first;

            found = true;
        }
    }
    std::cout << "}\n--------------------------------" << std::endl;
}

//This function clears a percentage of primed cache sets which might have been touched during the context switch
//This percentage is configurable
void customMapClear(SetTimeWay & mapPrimedCacheSet){
    if (mapClearPercentage == 0){
        //do nothing
    }
    else if (mapClearPercentage == 100){
        mapPrimedCacheSet.clear();
    }
    else {
        std::vector<unsigned int> primed_sets;
        for (auto & itr : mapPrimedCacheSet)
            primed_sets.push_back(itr.first);

        std::random_device rd;
        std::mt19937 g(rd());
        std::shuffle(primed_sets.begin(), primed_sets.end(), g);

        double percentage = (double)mapClearPercentage/100.0;
        int limit = percentage * primed_sets.size();


        for (int i = 0; i < limit/2; i++){
            auto S = mapPrimedCacheSet.find(primed_sets[i]);
            if (S != mapPrimedCacheSet.end())
                mapPrimedCacheSet.erase(S);
        }
    }
}

//This function adds all the primed cache sets of mapPrimedCacheSet2 to mapPrimedCacheSet1
SetTimeWay mergeMaps(SetTimeWay & mapPrimedCacheSet1, SetTimeWay & mapPrimedCacheSet2){
    for (auto & itr : mapPrimedCacheSet2){
        auto itr2 = mapPrimedCacheSet1.find(itr.first);
        if (itr2 != mapPrimedCacheSet1.end()) {//if it exists then merge the way vectors
            for (auto p = itr.second.begin(); p != itr.second.end(); p++){
                itr2->second.push_back(*p);
            }
        }
        else
            mapPrimedCacheSet1.insert(itr);
    }

    return mapPrimedCacheSet1;
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
    std::string pred_tag = "system." + cpu_name + ".branchPred";
    if (str.find(pred_tag) != std::string::npos && str.find("Lookup") != std::string::npos){
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

void setWayFind(const std::string& str, SetTimeWay & mapPrimedCacheSet) {
    std::size_t setColonPos = str.find("set: ");
    std::size_t wayColonPos = str.find("way: ");
    if (setColonPos != std::string::npos && wayColonPos != std::string::npos) {
        std::size_t pos = setColonPos + 5;
        std::string setHex = str.substr(pos, wayColonPos - pos - 1);
        std::string wayHex = str.substr(wayColonPos + 5);

        unsigned int setNum = std::stoul(setHex, nullptr, 16);
        unsigned int wayNum = std::stoul(wayHex, nullptr, 16);
        long long int time = getTimeStamp(str);
        auto itr = mapPrimedCacheSet.find(setNum);
        if (itr == mapPrimedCacheSet.end()) {
            std::vector<std::pair<long long int, unsigned int>> ways;
            ways.emplace_back(time, wayNum);
            mapPrimedCacheSet.insert(std::pair <unsigned int, std::vector<std::pair<long long int, unsigned int>>>(setNum, ways));
        } else {
            if (std::find(itr->second.begin(), itr->second.end(), std::make_pair(time, wayNum)) == itr->second.end())
                itr->second.emplace_back(time, wayNum);
        }
    }
}

void updateFrameBuffer(int F){
    if (!buffer.empty()){
        int count = 0;
        for (int i = 0; i < buffer.size(); i++){
            if (getTimeStamp(buffer[i]) / frame < F){
                count++;
            }
            else
                break;
        }

        buffer.erase(buffer.begin(), buffer.begin()+count);
    }
}

void checkHitAccess(const std::string& str, SetTimeWay & mapPrimedCacheSet) {
    std::string dcache_tag = "system." + cpu_name + ".dcache";
    if (str.find("hit") != std::string::npos && str.find(dcache_tag) != std::string::npos) {
        setWayFind(str, mapPrimedCacheSet);
    }
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
            if (std::getline(file, out)){
                return out;
            }
            return "-";
        }
    } else {
        if (std::getline(file, out)){
            return out;
        }
        return "-";
    }
}

std::string getNextLineQ(std::ifstream& file, std::string str = "") {
    if (!str.empty())
        return str;
    std::string out = "";
    if (readFromBuffer) {
        if (!Queue.empty()) {
            out = Queue.front();
            Queue.pop();
            return out;
        } else {
            readFromBuffer = false;
            if (std::getline(file, out)){
                return out;
            }
            return "-";
        }
    } else {
        if (std::getline(file, out)){
            return out;
        }
        return "-";
    }
}

bool checkMissAccess(std::ifstream& file, const std::string& str, SetTimeWay & mapPrimedCacheSet) {

    std::string dcache_tag = "system." + cpu_name + ".dcache";

    if (str.find("miss") != std::string::npos && str.find(dcache_tag) != std::string::npos) {
        readFromBuffer = false;

        while (true) {
            std::string nextStr = getNextLineQ(file);
            if (nextStr == "-")
                break;
            if (nextStr.find("Block addr") != std::string::npos && nextStr.find(dcache_tag) != std::string::npos) {
                // similar to hit, parse string and find set/way and write to map
                setWayFind(nextStr, mapPrimedCacheSet);
                break;
            } else {
                Queue.push(nextStr);
                nextStr = "";
            }
        }
        readFromBuffer = true;
        return true;
    }
    return false;
}

//This function checks if a potential victim accesses one of the primed cache sets
//This function runs only if event one(a sufficient number of cache sets are primed) has happened
bool checkSecondEvent(std::ifstream& file, std::string& str,
                              SetTimeWay & mapPrimedCacheSet,
                              std::vector<Victim>& output) {

    SetTimeWay newMapPrimedCacheSet; //This map contains all the cache misses in this frame
    SetTimeWay hitMapPrimedCacheSet; //This map combined with newMapPrimedCacheSet with have all accesses in this frame
    bool squashSeen = false;
    int countMiss = 0;
    int allMisses = 0;
    bool isAttacker = false;//This is the alert
    std::string tempStr = str;
    long long int t1 = getTimeStamp(str);
    std::set<std::string> LookedUpBranches;
    bool MissFound = false;

    while (true) {
        std::string currentStr = getNextLineQ(file, tempStr);
        str = currentStr;
        tempStr = "";

        if (MissFound){
            MissFound = false;
        }

        if (currentStr == "-")
            break;

        checkHitAccess(str, hitMapPrimedCacheSet);

        if (getTimeStamp(currentStr) / frame > frame_count)      // this frame is finished
            break;
        //Make sure to check for misses and squash after a branch lookup
        if (isBranchLookup(currentStr)){
            LookedUpBranches.insert(returnBranchLookup(currentStr));
        }
        if (checkMissAccess(file, currentStr, newMapPrimedCacheSet) && !LookedUpBranches.empty()) {
            allMisses ++;
            MissFound =true;
        }

        if (currentStr.find("Squash") != std::string::npos) {
            std::string BR = findBranchSquash(currentStr);
            if (!newMapPrimedCacheSet.empty()) {
				//only the first squash matters that theres has been a miss in its speculation window
                auto BRfound = LookedUpBranches.find(BR);

                if (!squashSeen && BRfound != LookedUpBranches.end()) {
					//The branch of this squash is among the looked up branches
                    squashSeen = true;
                    countMiss = allMisses;

                    //pruning the newMapPrimedCacheSet: Only keeping the cache sets existing in mapPrimedCacheSet
                    SetTimeWay tempMapPrimedCacheSet = newMapPrimedCacheSet; //taking a checkpoint before pruning
                    for (auto & itr : newMapPrimedCacheSet)
                    {
                        auto itr2 = mapPrimedCacheSet.find(itr.first);
                        if (itr2 == mapPrimedCacheSet.end()) {
                            newMapPrimedCacheSet.erase(itr.first);
                        }
                    }

                    if (newMapPrimedCacheSet.size() == 1){//only one set of primed sets should have been accessed
                        for (auto & itr : newMapPrimedCacheSet){
                            auto primedSet = mapPrimedCacheSet.find(itr.first);
                            //(1) all the ways of the primed set should have been accessed, 
                            //(2) only one way of the missed accsessed set should have been accessed in this frame
                            std::set<unsigned int> way_set; //a set of cache ways accessed
                            way_set.clear();
                            for (auto q = (primedSet->second).begin(); q != (primedSet->second).end(); q++)
                                way_set.insert((*q).second);

                            if (way_set.size() >= way && itr.second.size() == 1){
                                isAttacker = true;
                                for (auto p = itr.second.begin(); p != itr.second.end(); p++) {
                                    Victim victim;
                                    victim.set = itr.first;
                                    victim.way = (*p).second;
                                    victim.time = (*p).first;
                                    victim.branch = BR;
                                    output.push_back(victim);
                                }
                            }
                            else if (way_set.size() < way)
                                num_squahed_speculative_accesses_not_primed++;
                        }
                    }
                    else
                        num_squahed_speculative_accesses_multVictimAccesses++;

                    newMapPrimedCacheSet = tempMapPrimedCacheSet; //making sure we restore newMapPrimedCacheSet after the pruning
                    LookedUpBranches.erase(BRfound);
                }
            } 
            else {    // only notice to first Squash
                LookedUpBranches.erase(BR);
            }

            // check if # of miss accesses has increased or not. if yes -> no output(unsuccessful attack)
            if (allMisses > countMiss) {
                isAttacker = false;
                num_squahed_speculative_accesses_multVictimAccesses++;
                output.clear();
            }
        }
    }

    if (output.size() == 1){
        isAttacker = true;
        for (auto it = output.begin(); it != output.end(); it++){
            std::cout << "\n[Leakage] ";
            std::cout << (*it).branch << "   ";
            std::cout << "set: " << (*it).set << "     way: " << (*it).way <<
                    "   time: " << (*it).time << std::endl;
            printMap(mapPrimedCacheSet);
        }
    }
    else if (output.size() > 1){
        num_multi_interfering_leakages++;
        isAttacker = false;
    }

   if (!newMapPrimedCacheSet.empty() && !squashSeen)
        num_speculative_accessed_not_squashed++;

    if(!isAttacker){
        mergeMapPrimedCacheSet.clear();
        mergeMapPrimedCacheSet = mergeMaps(newMapPrimedCacheSet, hitMapPrimedCacheSet);
    }

    return isAttacker;
}


int main(int argc, char** argv) {
    std::string file_name = argv[1];
    std::ifstream file(file_name);
    std::cout << std::setw(45) << "The input report file: " << file_name << std::endl;

    std::string set_str = argv[2];
    set = std::stoi(set_str);
    std::cout << std::setw(45) << "The number of required primed cache sets: " << set << std::endl;

    std::string way_str = argv[3];
    way = std::stoi(way_str);
    std::cout << std::setw(45) << "The number of cache ways: " << way << std::endl;

    std::string frame_str = argv[4];
    frame = std::stoi(frame_str);
    std::cout << std::setw(45) << "Frame size: " << frame << std::endl;

    std::string mode_str = argv[5];
    mapClearPercentage = std::stoi(mode_str);
    std::cout << std::setw(45) << "Percentage of Map to clear during CS: " << mapClearPercentage << std::endl;
    assert(mapClearPercentage >= 0 && mapClearPercentage <= 100 && "Map Clear Percentage needs to be bwtween 0-100");

    cpu_name = argv[6];    
	std::cout << std::setw(45) << "CPU name in the gem5 stats: " << cpu_name << std::endl;

    std::string tick_str = argv[7];
    initial_tick = std::stol(tick_str);
    std::cout << std::setw(45) << "Initial tick: " << initial_tick << std::endl;
	
	std::string interval_str = argv[8];
    stat_interval = std::stoi(interval_str);
    std::cout << std::setw(45) << "Dump stats interval: " << stat_interval << std::endl;

    std::string str;
    long long int currentFrame = 0;
    SetTimeWay mapPrimedCacheSet;

    bool new_frame = false;
    long long int frame_start_time;
    bool frame_start_seen = false;

    //initializing the stats to zero
    init_stats();

    while (true)
    {
        str = getNextLineQ(file);
        if (str == "-")
            break;

        if (new_frame){
            new_frame = false;
        }

        long long int time = getTimeStamp(str);
        if (time <= 0)
            continue;

        if ((time / frame > currentFrame) || (time == frame_start_time && frame_start_seen)) {

            if (time != frame_start_time){
                averagePrimed(mapPrimedCacheSet, frame_count);
                frame_count++;

                if (frame_count % stat_interval == 0){
                    dump_stats();
                }
            }
            
            long long int oldCurrentFrame = currentFrame;
            currentFrame = time / frame;
            if (checkEventOne(mapPrimedCacheSet)) {
                event_one_count++;

                std::vector<Victim> output;
                if (checkSecondEvent(file, str, mapPrimedCacheSet, output)) {
                    num_leakages++;
                    // this frame is attacker. reset map and print output
                    mapPrimedCacheSet.clear();//if the leakage found --> clear the primed map
                } else {
                    // check for event one (victim)
					// merge mapPrimedCacheSet and M if second event didn't happen 
                    mapPrimedCacheSet = mergeMaps(mapPrimedCacheSet, mergeMapPrimedCacheSet);
					// clearing the mapPrimedCacheSet (based on the configurable input percentage)
    				customMapClear(mapPrimedCacheSet);
                }

                averagePrimed(mapPrimedCacheSet, frame_count);
                frame_count++;
                if (frame_count % stat_interval == 0){
        		    dump_stats();
                }
	            currentFrame = getTimeStamp(str) / frame;
                frame_start_time = getTimeStamp(str);
                frame_start_seen = true;
                new_frame = true;

            } else {
                // clearing the mapPrimedCacheSet (based on the configurable input percentage)
				customMapClear(mapPrimedCacheSet);
                // analyze new frame just for event one
                checkHitAccess(str, mapPrimedCacheSet);
                checkMissAccess(file, str, mapPrimedCacheSet);
            }

        } else {
            // still search and analyze event1 in current frame
            checkHitAccess(str, mapPrimedCacheSet);
            checkMissAccess(file, str, mapPrimedCacheSet);
        }
    }

    dump_stats();

    return 0;
}
