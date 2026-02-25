#include <windows.h>
#include <wininet.h>
#include <winsvc.h>
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <ctime>
#include <fstream>
#include <thread>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <set>
#include <queue>
#include <atomic>
#include <chrono>
#include <psapi.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

#define APP_VERSION "2.1-Enterprise"

// --- CONFIGURAZIONE ---
struct Config {
    std::string ip;
    int port;
    std::string user;
    std::string pass;
    std::string localDir;
    std::string remoteDir;
    int pollIntervalMs = 10000;
};

Config g_config;
std::mutex g_logMutex;
std::mutex g_stateMutex;
bool g_running = true;
SERVICE_STATUS g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE g_StatusHandle = nullptr;
std::string g_appPath;

// --- STATO SINCRONIZZAZIONE ---
std::map<std::string, time_t> g_recentlyProcessed;
std::map<std::string, time_t> g_locallyDeleted;
std::atomic<time_t> g_lastLocalDeleteTime(0);
const int DELETE_PAUSE_THRESHOLD_SEC = 10; 

// --- LOGGER CLASS (AVANZATO) ---
class Logger {
    std::string logDir;
    std::ofstream seqFile;
    std::ofstream threadFile;
    
    std::string currentDayStr;
    
    struct DailyStats {
        std::atomic<int> countUploads{0};
        std::atomic<int> countDownloads{0};
        std::atomic<int> countDeletes{0};
        std::atomic<int> countRenames{0};
        std::atomic<int> countErrors{0};
        
        std::atomic<unsigned long long> bytesUp{0};
        std::atomic<unsigned long long> bytesDown{0};
        
        std::atomic<int> activeThreads{0};
        std::atomic<int> peakThreads{0};
        
        std::chrono::steady_clock::time_point startTime;
    } stats;

    std::map<DWORD, DWORD> threadParents; 
    std::map<DWORD, std::string> threadNames;
    std::map<DWORD, std::chrono::steady_clock::time_point> threadStartTimes; 
    std::map<DWORD, std::chrono::steady_clock::time_point> lastEventTime;
    std::map<DWORD, std::string> threadLastState; 

    std::string FormatTime(std::chrono::system_clock::time_point now) {
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
        
        std::stringstream ss;
        tm t;
        localtime_s(&t, &in_time_t); 
        ss << std::put_time(&t, "[%d/%m %H:%M:%S");
        ss << "." << std::setfill('0') << std::setw(3) << ms.count() << "]";
        return ss.str();
    }

    std::string GetDate() {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        tm t;
        localtime_s(&t, &in_time_t);
        ss << std::put_time(&t, "%Y-%m-%d");
        return ss.str();
    }
    
    void WriteToFiles(const std::string& lineSeq, const std::string& lineThread) {
        std::lock_guard<std::mutex> lock(g_logMutex);
        
        std::string today = GetDate();
        if (today != currentDayStr) {
            if (!currentDayStr.empty()) {
                WriteSummaryInternal(true); 
            }
            
            stats.countUploads = 0; stats.countDownloads = 0; stats.countDeletes = 0;
            stats.countRenames = 0; stats.countErrors = 0;
            stats.bytesUp = 0; stats.bytesDown = 0;
            stats.peakThreads = 0;
            stats.startTime = std::chrono::steady_clock::now();
            currentDayStr = today;
            
            if(seqFile.is_open()) seqFile.close();
            if(threadFile.is_open()) threadFile.close();
            
            seqFile.open(logDir + "\\" + currentDayStr + "_sequential.log", std::ios::app);
            threadFile.open(logDir + "\\" + currentDayStr + "_thread.log", std::ios::app);
            
            if (seqFile.is_open()) {
                seqFile << std::string(80, '=') << "\n";
                seqFile << "  NEW DAY STARTED: " << currentDayStr << "\n";
                seqFile << std::string(80, '=') << "\n\n";
                seqFile.flush();
            }
            if (threadFile.is_open()) {
                auto now = std::chrono::system_clock::now();
                std::string ts = FormatTime(now);
                threadFile << ts << " " << std::string(80, '=') << "\n";
                threadFile << ts << "   NEW DAY STARTED: " << currentDayStr << "\n";
                threadFile << ts << " " << std::string(80, '=') << "\n\n";
                threadFile.flush();
            }
        }

        if (seqFile.is_open() && !lineSeq.empty()) {
            seqFile << lineSeq << "\n";
            seqFile.flush();
        }
        if (threadFile.is_open() && !lineThread.empty()) {
            threadFile << lineThread << "\n";
            threadFile.flush();
        }
    }

    void WriteSummaryInternal(bool isEndOfDay) {
        if (!seqFile.is_open()) return;
        
        auto now_sys = std::chrono::system_clock::now();
        std::string ts = FormatTime(now_sys);
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - stats.startTime).count();

        std::string header = isEndOfDay ? "=== DAILY SUMMARY ===" : "=== PERIODIC REPORT (10m) ===";

        PROCESS_MEMORY_COUNTERS pmc;
        SIZE_T workingSet = 0;
        if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
            workingSet = pmc.WorkingSetSize;
        }

        auto formatBytes = [](unsigned long long bytes) {
            std::stringstream ss;
            ss << std::fixed << std::setprecision(2);
            if (bytes < 1024) ss << bytes << " B";
            else if (bytes < 1024 * 1024) ss << (bytes / 1024.0) << " KB";
            else if (bytes < 1024 * 1024 * 1024) ss << (bytes / (1024.0 * 1024.0)) << " MB";
            else ss << (bytes / (1024.0 * 1024.0 * 1024.0)) << " GB";
            return ss.str();
        };

        seqFile << "\n" << ts << " " << header << "\n";
        seqFile << ts << " Uptime: " << duration << "s\n";
        seqFile << ts << " --- Traffic ---\n";
        seqFile << ts << "   Uploads:   " << stats.countUploads << " files (" << formatBytes(stats.bytesUp) << ")\n";
        seqFile << ts << "   Downloads: " << stats.countDownloads << " files (" << formatBytes(stats.bytesDown) << ")\n";
        seqFile << ts << "   Deletes:   " << stats.countDeletes << " ops\n";
        seqFile << ts << "   Renames:   " << stats.countRenames << " ops\n";
        seqFile << ts << "   Errors:    " << stats.countErrors << "\n";
        seqFile << ts << " --- System ---\n";
        seqFile << ts << "   Memory Usage: " << formatBytes(workingSet) << "\n";
        seqFile << ts << "   Active Threads: " << stats.activeThreads << " (Peak: " << stats.peakThreads << ")\n";
        
        if (!isEndOfDay) {
            seqFile << ts << "   Active Threads Status:\n";
            for (auto const& [tid, name] : threadNames) {
                if (threadStartTimes.count(tid)) {
                    auto threadLife = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - threadStartTimes[tid]).count();
                    auto lastAct = threadLastState.count(tid) ? threadLastState[tid] : "IDLE";
                    seqFile << ts << "     -> [" << name << "] TID:" << tid << " Life:" << threadLife << "s State: " << lastAct << "\n";
                }
            }
        }
        seqFile << ts << " " << std::string(60, '-') << "\n\n";
        seqFile.flush();
    }

public:
    void WritePeriodicSummary() {
        std::lock_guard<std::mutex> lock(g_logMutex);
        WriteSummaryInternal(false);
    }

    void EnsureDirExists(const std::string& path) {
        CreateDirectoryA(path.c_str(), NULL);
    }

    int GetThreadDepth(DWORD tid) {
        int depth = 0;
        DWORD curr = tid;
        while (threadParents.count(curr) && threadParents[curr] != curr) {
            curr = threadParents[curr];
            depth++;
        }
        return depth;
    }

    std::string GetIndent(DWORD tid) {
        int depth = GetThreadDepth(tid);
        std::string indent;
        for (int i = 0; i < depth; ++i) indent += "    ";
        return indent;
    }

    void Init(const std::string& basePath) {
        logDir = basePath + "\\log";
        EnsureDirExists(logDir);
        currentDayStr = ""; 
        stats.startTime = std::chrono::steady_clock::now();
    }

    void RegisterThread(DWORD tid, const std::string& name, DWORD parentTid) {
        auto now_sys = std::chrono::system_clock::now();
        auto now_steady = std::chrono::steady_clock::now();

        {
            std::lock_guard<std::mutex> lock(g_logMutex); 
            threadNames[tid] = name;
            if (parentTid == 0 || parentTid == tid) threadParents[tid] = tid;
            else threadParents[tid] = parentTid;
            
            threadStartTimes[tid] = now_steady;
            lastEventTime[tid] = now_steady;
            threadLastState[tid] = "STARTED";

            stats.activeThreads++;
            if (stats.activeThreads > stats.peakThreads) {
                stats.peakThreads = stats.activeThreads.load();
            }
        }

        std::string ts = FormatTime(now_sys);
        std::string lineSeq = ts + " [SYSTEM] Thread Started: " + name + " [TID:" + std::to_string(tid) + "]";
        
        std::string indent = GetIndent(tid);
        std::string parentName = "ROOT";
        { 
            std::lock_guard<std::mutex> lock(g_logMutex);
            if(threadNames.count(parentTid)) parentName = threadNames[parentTid];
        }
        
        std::stringstream ssThread;
        if (parentTid != tid && parentTid != 0) {
            ssThread << ts << indent << "   | \n";
            ssThread << ts << indent << "   +---> [SPAWN] \n";
        }
        ssThread << ts << indent << "   " << std::string(60, '-') << "\n";
        ssThread << ts << indent << "   | THREAD START: " << std::setw(12) << name << " [TID:" << tid << "]\n";
        ssThread << ts << indent << "   | Generator:    " << parentName << " [TID:" << parentTid << "]\n";
        ssThread << ts << indent << "   " << std::string(60, '-') << "\n";

        WriteToFiles(lineSeq, ssThread.str());
    }

    void WriteSeqAndStats(DWORD tid, const std::string& workflow, const std::string& msg, int type = 0, unsigned long long bytes = 0) {
        auto now_sys = std::chrono::system_clock::now();
        auto now_steady = std::chrono::steady_clock::now();

        switch(type) {
            case 1: stats.countUploads++; stats.bytesUp += bytes; break;
            case 2: stats.countDownloads++; stats.bytesDown += bytes; break;
            case 3: stats.countDeletes++; break;
            case 4: stats.countRenames++; break;
            case 5: stats.countErrors++; break;
        }

        std::string name = "UNK";
        long long deltaMs = 0;
        std::string indent = GetIndent(tid);
        std::string stateMsg = workflow + " " + msg;

        { 
            std::lock_guard<std::mutex> lock(g_logMutex); 
            if(threadNames.count(tid)) name = threadNames[tid];
            if(lastEventTime.count(tid)) {
                deltaMs = std::chrono::duration_cast<std::chrono::milliseconds>(now_steady - lastEventTime[tid]).count();
                lastEventTime[tid] = now_steady;
            }
            threadLastState[tid] = stateMsg;
        }
        
        std::string ts = FormatTime(now_sys);
        std::string lineSeq = ts + " [" + name + "] [" + workflow + "] " + msg;
        std::string lineThread = ts + indent + "   | [INFO]    " + stateMsg + " (Δ " + std::to_string(deltaMs) + "ms)";

        WriteToFiles(lineSeq, lineThread);
    }

    void LogFlow(DWORD tid, int flowType, const std::string& msg) {
        auto now_sys = std::chrono::system_clock::now();
        auto now_steady = std::chrono::steady_clock::now();

        long long deltaMs = 0;
        std::string indent = GetIndent(tid);
        std::string stateMsg = msg;
        
        { 
            std::lock_guard<std::mutex> lock(g_logMutex); 
            if(lastEventTime.count(tid)) {
                deltaMs = std::chrono::duration_cast<std::chrono::milliseconds>(now_steady - lastEventTime[tid]).count();
                lastEventTime[tid] = now_steady;
            }
            threadLastState[tid] = msg;
        }

        std::string prefix;
        std::string prefixSeq;
        switch(flowType) {
            case 1: prefix = "| [START]   "; prefixSeq = "[START]"; break;
            case 2: prefix = "| [END]     "; prefixSeq = "[END]"; break;
            case 3: prefix = "| [PAUSE]   "; prefixSeq = "[PAUSE]"; break;
            case 4: prefix = "| [RESUME]  "; prefixSeq = "[RESUME]"; break;
            case 5: prefix = "| [ERROR]   "; prefixSeq = "[ERROR]"; break;
            default: prefix = "| [INFO]    "; prefixSeq = "[INFO]"; break;
        }

        std::string ts = FormatTime(now_sys);
        std::string name = "UNK";
        { std::lock_guard<std::mutex> lock(g_logMutex); if(threadNames.count(tid)) name = threadNames[tid]; }
        
        std::string lineSeq = ts + " [" + name + "] " + prefixSeq + " " + msg;
        std::string lineThread = ts + indent + "   " + prefix + msg + " (Δ " + std::to_string(deltaMs) + "ms)";

        WriteToFiles(lineSeq, lineThread);
    }

    void LogDestruction(DWORD tid) {
        auto now_sys = std::chrono::system_clock::now();
        
        std::string name = "UNK";
        int lifetime = 0;
        std::string indent = GetIndent(tid);
        
        { 
            std::lock_guard<std::mutex> lock(g_logMutex);
            if(threadNames.count(tid)) name = threadNames[tid];
            if(threadStartTimes.count(tid)) 
                lifetime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - threadStartTimes[tid]).count();
            
            threadParents.erase(tid);
            threadNames.erase(tid);
            threadLastState.erase(tid);
            stats.activeThreads--;
        }

        std::string ts = FormatTime(now_sys);
        std::string lineSeq = ts + " [SYSTEM] Thread Ended: " + name + " [TID:" + std::to_string(tid) + "] Lifetime: " + std::to_string(lifetime) + "s";

        std::stringstream ssThread;
        ssThread << ts << indent << "   | \n";
        ssThread << ts << indent << "   " << std::string(60, '-') << "\n";
        ssThread << ts << indent << "   | THREAD END: " << std::setw(12) << name << " [TID:" << tid << "]\n";
        ssThread << ts << indent << "   | Lifetime: " << lifetime << " seconds\n";
        ssThread << ts << indent << "   " << std::string(60, '-') << "\n\n";

        WriteToFiles(lineSeq, ssThread.str());
    }

    void Heartbeat(DWORD mainTid) {
        auto now_sys = std::chrono::system_clock::now();
        std::string ts = FormatTime(now_sys);
        std::string lineSeq = ts + " [SERVICE_MAIN] [HEARTBEAT] Service Running. Monitoring active.";
        WriteToFiles(lineSeq, "");
    }

    void LogConfig(const std::string& iniPath, const Config& cfg) {
        auto now_sys = std::chrono::system_clock::now();
        std::string ts = FormatTime(now_sys);
        
        std::stringstream ss;
        ss << ts << " [CONFIG] Loading configuration from: " << iniPath << "\n";
        ss << ts << " [CONFIG] Version: " << APP_VERSION << "\n";
        ss << ts << " [CONFIG] IP: " << cfg.ip << ":" << cfg.port << "\n";
        ss << ts << " [CONFIG] User: " << cfg.user << "\n";
        ss << ts << " [CONFIG] Local Folder: " << cfg.localDir << "\n";
        ss << ts << " [CONFIG] Remote Folder: " << cfg.remoteDir << "\n";
        ss << ts << " [CONFIG] Poll Interval: " << (cfg.pollIntervalMs/1000) << "s\n";

        WriteToFiles(ss.str(), ""); 
    }
};

Logger g_logger;

// Helper globali
void Log(const std::string& workflow, const std::string& msg, int statType = 0, unsigned long long bytes = 0) {
    g_logger.WriteSeqAndStats(GetCurrentThreadId(), workflow, msg, statType, bytes);
}

void LogFlow(int flowType, const std::string& msg) {
    g_logger.LogFlow(GetCurrentThreadId(), flowType, msg);
}

void RegisterThread(const std::string& name, DWORD parentTid) {
    g_logger.RegisterThread(GetCurrentThreadId(), name, parentTid);
}

// --- UTILITIES ---
unsigned long long GetFileSize(const std::string& path) {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &fad)) {
        ULARGE_INTEGER ul;
        ul.LowPart = fad.nFileSizeLow;
        ul.HighPart = fad.nFileSizeHigh;
        return ul.QuadPart;
    }
    return 0;
}

bool LoadConfig(const std::string& iniPath) {
    char buffer[512];
    
    GetPrivateProfileStringA("FTP", "IP", "", buffer, 512, iniPath.c_str());
    g_config.ip = buffer;
    g_config.port = GetPrivateProfileIntA("FTP", "Port", 21, iniPath.c_str());
    GetPrivateProfileStringA("FTP", "User", "", buffer, 512, iniPath.c_str());
    g_config.user = buffer;
    GetPrivateProfileStringA("FTP", "Password", "", buffer, 512, iniPath.c_str());
    g_config.pass = buffer;
    GetPrivateProfileStringA("FTP", "LocalFolder", "", buffer, 512, iniPath.c_str());
    g_config.localDir = buffer;
    if (!g_config.localDir.empty() && g_config.localDir.back() != '\\') g_config.localDir += '\\';
    GetPrivateProfileStringA("FTP", "RemoteFolder", "", buffer, 512, iniPath.c_str());
    g_config.remoteDir = buffer;
    if (!g_config.remoteDir.empty() && g_config.remoteDir.back() != '/') g_config.remoteDir += '/';

    g_logger.LogConfig(iniPath, g_config);
    return !g_config.ip.empty() && !g_config.localDir.empty();
}

std::string ToRemotePath(const std::string& relativePath) {
    std::string res = relativePath;
    std::replace(res.begin(), res.end(), '\\', '/');
    return g_config.remoteDir + res;
}

std::string ToLocalRelativePath(const std::string& remoteFullPath) {
    if (remoteFullPath.find(g_config.remoteDir) == 0) {
        std::string res = remoteFullPath.substr(g_config.remoteDir.length());
        std::replace(res.begin(), res.end(), '/', '\\');
        return res;
    }
    return remoteFullPath;
}

// --- STATE MANAGEMENT ---
bool CheckAndClearRecentAction(const std::string& key) {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    auto it = g_recentlyProcessed.find(key);
    if (it != g_recentlyProcessed.end()) {
        if (time(NULL) - it->second < 5) return true;
        g_recentlyProcessed.erase(it);
    }
    return false;
}

void MarkRecentAction(const std::string& key) {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    g_recentlyProcessed[key] = time(NULL);
}

bool IsLocallyDeleted(const std::string& relativePath) {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    return g_locallyDeleted.count(relativePath) > 0;
}

void MarkBatchLocallyDeleted(const std::vector<std::string>& paths) {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    time_t now = time(NULL);
    for (const auto& p : paths) g_locallyDeleted[p] = now;
    g_lastLocalDeleteTime = now;
}

void ClearLocallyDeleted(const std::string& relativePath) {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    g_locallyDeleted.erase(relativePath);
}

void CleanupOldDeletedEntries() {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    time_t now = time(NULL);
    for (auto it = g_locallyDeleted.begin(); it != g_locallyDeleted.end(); ) {
        if (now - it->second > 60) it = g_locallyDeleted.erase(it);
        else ++it;
    }
}

// --- FTP WRAPPER ---
class FtpSession {
    HINTERNET hInternet = nullptr;
    HINTERNET hConnect = nullptr;
public:
    bool Connect() {
        hInternet = InternetOpenA("FTPSyncService", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (!hInternet) return false;
        hConnect = InternetConnectA(hInternet, g_config.ip.c_str(), g_config.port,
            g_config.user.c_str(), g_config.pass.c_str(), INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
        return hConnect != nullptr;
    }

    ~FtpSession() {
        if (hConnect) InternetCloseHandle(hConnect);
        if (hInternet) InternetCloseHandle(hInternet);
    }

    void EnsureRemoteDirectoryExists(std::string remotePath) {
        size_t lastSlash = remotePath.find_last_of('/');
        if (lastSlash != std::string::npos) {
            std::string dirPath = remotePath.substr(0, lastSlash);
            std::vector<std::string> parts;
            std::stringstream ss(dirPath);
            std::string temp;
            while (std::getline(ss, temp, '/')) if (!temp.empty()) parts.push_back(temp);
            std::string currentPath = "";
            for (size_t i = 0; i < parts.size(); i++) {
                currentPath += "/" + parts[i];
                FtpCreateDirectoryA(hConnect, currentPath.c_str());
            }
        }
    }

    bool UploadFile(const std::string& localPath, const std::string& remotePath) {
        EnsureRemoteDirectoryExists(remotePath);
        unsigned long long size = GetFileSize(localPath);
        Log("UPLOAD", "File: " + localPath + " (" + std::to_string(size) + " bytes)", 1, size);
        return FtpPutFileA(hConnect, localPath.c_str(), remotePath.c_str(), FTP_TRANSFER_TYPE_BINARY, 0) == TRUE;
    }

    bool DeleteRemoteFile(const std::string& remotePath) {
        Log("DELETE", "Path: " + remotePath, 3);
        BOOL ret = FtpDeleteFileA(hConnect, remotePath.c_str());
        if (!ret) ret = FtpRemoveDirectoryA(hConnect, remotePath.c_str());
        return ret == TRUE;
    }

    bool RenameRemoteFile(const std::string& oldRemote, const std::string& newRemote) {
        Log("RENAME", oldRemote + " -> " + newRemote, 4);
        if (FtpRenameFileA(hConnect, oldRemote.c_str(), newRemote.c_str())) return true;
        EnsureRemoteDirectoryExists(newRemote);
        return false;
    }

    bool DownloadFile(const std::string& remotePath, const std::string& localPath) {
        size_t lastSlash = localPath.find_last_of('\\');
        if (lastSlash != std::string::npos) {
            std::string dir = localPath.substr(0, lastSlash);
            std::vector<std::string> parts;
            std::stringstream ss(dir);
            std::string segment;
            std::string currentPath = "";
            while(std::getline(ss, segment, '\\')) {
                currentPath += segment + "\\";
                CreateDirectoryA(currentPath.c_str(), NULL);
            }
        }
        
        BOOL res = FtpGetFileA(hConnect, remotePath.c_str(), localPath.c_str(), FALSE, FILE_ATTRIBUTE_NORMAL, FTP_TRANSFER_TYPE_BINARY, 0);
        
        if (res) {
            unsigned long long size = GetFileSize(localPath);
            Log("DOWNLOAD", "File: " + localPath + " (" + std::to_string(size) + " bytes)", 2, size);
        }
        return res == TRUE;
    }

    struct RemoteItem { std::string path; bool isDir; FILETIME time; };

    std::vector<RemoteItem> ListDirectory(const std::string& remoteDir) {
        std::vector<RemoteItem> items;
        WIN32_FIND_DATAA findData;
        std::string searchPath = remoteDir;
        if (!searchPath.empty() && searchPath.back() != '/') searchPath += "/";
        searchPath += "*";
        HINTERNET hFind = FtpFindFirstFileA(hConnect, searchPath.c_str(), &findData, 0, 0);
        if (hFind) {
            do {
                std::string name = findData.cFileName;
                if (name == "." || name == "..") continue;
                RemoteItem item;
                item.isDir = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
                item.time = findData.ftLastWriteTime;
                std::string fullPath = remoteDir;
                if (!fullPath.empty() && fullPath.back() != '/') fullPath += "/";
                fullPath += name;
                item.path = fullPath;
                items.push_back(item);
            } while (InternetFindNextFileA(hFind, &findData));
            InternetCloseHandle(hFind);
        }
        return items;
    }
};

// --- THREADS ---

void SyncRemoteToLocal() {
    time_t lastDel = g_lastLocalDeleteTime.load();
    if (lastDel > 0 && (time(NULL) - lastDel < DELETE_PAUSE_THRESHOLD_SEC)) {
        LogFlow(3, "SYNC PAUSED (Local delete in progress)");
        return;
    }

    LogFlow(1, "FTP CONNECT & SYNC START");
    FtpSession ftp;
    if (!ftp.Connect()) {
        LogFlow(5, "FTP Connection Failed");
        return;
    }

    CleanupOldDeletedEntries();
    std::queue<std::string> dirQueue;
    dirQueue.push(g_config.remoteDir);

    while (!dirQueue.empty()) {
        std::string currentRemoteDir = dirQueue.front();
        dirQueue.pop();
        std::string relativeDir = ToLocalRelativePath(currentRemoteDir);
        std::string currentLocalDir = g_config.localDir + relativeDir;
        
        if (GetFileAttributesA(currentLocalDir.c_str()) == INVALID_FILE_ATTRIBUTES) {
             if (IsLocallyDeleted(relativeDir)) continue;
             CreateDirectoryA(currentLocalDir.c_str(), NULL);
        }

        auto items = ftp.ListDirectory(currentRemoteDir);
        for (auto& item : items) {
            if (item.isDir) {
                dirQueue.push(item.path);
            } else {
                std::string relativeFile = ToLocalRelativePath(item.path);
                if (IsLocallyDeleted(relativeFile)) continue;
                
                std::string localFile = g_config.localDir + relativeFile;
                bool needDownload = false;
                WIN32_FILE_ATTRIBUTE_DATA localAttr;
                if (GetFileAttributesExA(localFile.c_str(), GetFileExInfoStandard, &localAttr)) {
                    ULARGE_INTEGER uRemote, uLocal;
                    uRemote.LowPart = item.time.dwLowDateTime;
                    uRemote.HighPart = item.time.dwHighDateTime;
                    uLocal.LowPart = localAttr.ftLastWriteTime.dwLowDateTime;
                    uLocal.HighPart = localAttr.ftLastWriteTime.dwHighDateTime;
                    if (uRemote.QuadPart > uLocal.QuadPart) needDownload = true;
                } else needDownload = true;

                if (needDownload) {
                    MarkRecentAction(relativeFile);
                    ftp.DownloadFile(item.path, localFile);
                    HANDLE hFile = CreateFileA(localFile.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
                    if (hFile != INVALID_HANDLE_VALUE) {
                        SetFileTime(hFile, NULL, NULL, &item.time);
                        CloseHandle(hFile);
                    }
                }
            }
        }
    }
    LogFlow(2, "SYNC CYCLE COMPLETE");
}

void RemotePollerThread(DWORD parentTid) {
    RegisterThread("POLLER", parentTid);
    while (g_running) {
        SyncRemoteToLocal();
        LogFlow(3, "Sleeping for " + std::to_string(g_config.pollIntervalMs/1000) + "s");
        for(int i=0; i<g_config.pollIntervalMs/1000 && g_running; i++) Sleep(1000);
        LogFlow(4, "Waking up");
    }
    g_logger.LogDestruction(GetCurrentThreadId());
}

// --- WATCHER ---
typedef struct {
    OVERLAPPED overlapped;
    BYTE buffer[65536]; 
    HANDLE hDir;
} WATCHER_CONTEXT;

VOID CALLBACK FileChangeCallback(DWORD dwErrorCode, DWORD dwNumberOfBytesTransfered, LPOVERLAPPED lpOverlapped) {
    if (!g_running) return;
    WATCHER_CONTEXT* ctx = (WATCHER_CONTEXT*)lpOverlapped;

    if (dwErrorCode == ERROR_NOTIFY_ENUM_DIR) {
         Log("WATCHER_ERR", "Buffer Overflow", 5);
         if (g_running) {
             DWORD dwBytesReturned = 0;
             ReadDirectoryChangesW(ctx->hDir, ctx->buffer, sizeof(ctx->buffer), TRUE,
                 FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
                 &dwBytesReturned, &ctx->overlapped, FileChangeCallback);
         }
         return;
    }
    
    if (dwErrorCode != ERROR_SUCCESS || dwNumberOfBytesTransfered == 0) {
        if (g_running) {
             DWORD dwBytesReturned = 0;
             ReadDirectoryChangesW(ctx->hDir, ctx->buffer, sizeof(ctx->buffer), TRUE,
                 FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
                 &dwBytesReturned, &ctx->overlapped, FileChangeCallback);
        }
        return;
    }

    std::vector<std::pair<std::string, DWORD>> actions;
    FILE_NOTIFY_INFORMATION* pNotify = (FILE_NOTIFY_INFORMATION*)ctx->buffer;
    while (true) {
        char filename[MAX_PATH];
        int count = WideCharToMultiByte(CP_ACP, 0, pNotify->FileName, pNotify->FileNameLength / sizeof(WCHAR), filename, MAX_PATH-1, NULL, NULL);
        filename[count] = '\0';
        actions.push_back({std::string(filename), pNotify->Action});
        if (pNotify->NextEntryOffset == 0) break;
        pNotify = (FILE_NOTIFY_INFORMATION*)((BYTE*)pNotify + pNotify->NextEntryOffset);
    }

    std::vector<std::string> filesToDelete;
    std::vector<std::pair<std::string, std::string>> renames; 

    for (size_t i = 0; i < actions.size(); ++i) {
        auto& act = actions[i];
        if (act.second == FILE_ACTION_RENAMED_OLD_NAME) {
            if (i + 1 < actions.size() && actions[i+1].second == FILE_ACTION_RENAMED_NEW_NAME) {
                renames.push_back({act.first, actions[i+1].first});
                filesToDelete.push_back(act.first); 
                i++; 
            } else {
                filesToDelete.push_back(act.first);
            }
        } else if (act.second == FILE_ACTION_REMOVED) {
            filesToDelete.push_back(act.first);
        }
    }

    if (!filesToDelete.empty()) {
        Log("BATCH_OP", "Detected " + std::to_string(filesToDelete.size()) + " deletions/renames");
        LogFlow(1, "Batch Delete/Rename Marking");
        MarkBatchLocallyDeleted(filesToDelete);
        LogFlow(2, "Batch Delete/Rename Marked");
    }

    if (g_running) {
        DWORD dwBytesReturned = 0;
        ReadDirectoryChangesW(ctx->hDir, ctx->buffer, sizeof(ctx->buffer), TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
            &dwBytesReturned, &ctx->overlapped, FileChangeCallback);
    }

    try {
        FtpSession ftp;
        bool connected = false;

        for (auto& r : renames) {
            std::string oldRel = r.first;
            std::string newRel = r.second;
            ClearLocallyDeleted(oldRel); 

            if (!connected) { LogFlow(1, "FTP Connect for Rename"); connected = ftp.Connect(); }
            if (connected) {
                std::string oldRemote = ToRemotePath(oldRel);
                std::string newRemote = ToRemotePath(newRel);
                if (!ftp.RenameRemoteFile(oldRemote, newRemote)) {
                    ftp.DeleteRemoteFile(oldRemote);
                    std::string fullPath = g_config.localDir + newRel;
                    DWORD attrs = GetFileAttributesA(fullPath.c_str());
                    if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) ftp.UploadFile(fullPath, newRemote);
                }
            }
        }

        std::set<std::string> handledOldNames;
        for(auto& r : renames) handledOldNames.insert(r.first);

        for (auto& act : actions) {
            if (handledOldNames.count(act.first)) continue;
            if (act.second == FILE_ACTION_RENAMED_NEW_NAME || act.second == FILE_ACTION_ADDED || act.second == FILE_ACTION_MODIFIED) {
                std::string relativePath = act.first;
                std::string fullPath = g_config.localDir + relativePath;
                DWORD attrs = GetFileAttributesA(fullPath.c_str());
                bool isDir = (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY));
                ClearLocallyDeleted(relativePath);

                if (!isDir) {
                    if (!CheckAndClearRecentAction(relativePath)) {
                        if (!connected) { connected = ftp.Connect(); }
                        if (connected) {
                            Sleep(300);
                            ftp.UploadFile(fullPath, ToRemotePath(relativePath));
                        }
                    }
                }
            } else if (act.second == FILE_ACTION_REMOVED) {
                 if (!connected) { connected = ftp.Connect(); }
                 if (connected) ftp.DeleteRemoteFile(ToRemotePath(act.first));
            }
        }
    } catch (...) { Log("WATCHER_ERR", "Exception", 5); }
}

void LocalWatcherThread(DWORD parentTid) {
    RegisterThread("WATCHER", parentTid);
    WATCHER_CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    ctx.hDir = CreateFileA(g_config.localDir.c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
    if (ctx.hDir == INVALID_HANDLE_VALUE) {
        Log("WATCHER_ERR", "Cannot open directory", 5);
        g_logger.LogDestruction(GetCurrentThreadId());
        return;
    }

    LogFlow(1, "Monitoring Loop Started");
    DWORD dwBytesReturned = 0;
    ReadDirectoryChangesW(ctx.hDir, ctx.buffer, sizeof(ctx.buffer), TRUE, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE, &dwBytesReturned, &ctx.overlapped, FileChangeCallback);

    while (g_running) { SleepEx(INFINITE, TRUE); }
    CloseHandle(ctx.hDir);
    g_logger.LogDestruction(GetCurrentThreadId());
}

// --- SERVICE MAIN ---
void WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    if (CtrlCode == SERVICE_CONTROL_STOP) {
        g_running = false;
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    }
}

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    g_StatusHandle = RegisterServiceCtrlHandlerA("FTPSyncService", ServiceCtrlHandler);
    if (!g_StatusHandle) return;

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    std::string exePath(path);
    g_appPath = exePath.substr(0, exePath.find_last_of("\\/"));
    
    g_logger.Init(g_appPath);
    DWORD mainTid = GetCurrentThreadId();
    RegisterThread("SERVICE_MAIN", 0);

    if (!LoadConfig(g_appPath + "\\config.ini")) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    LogFlow(1, "Spawning Worker Threads");
    std::thread(LocalWatcherThread, mainTid).detach();
    std::thread(RemotePollerThread, mainTid).detach();

    int counterSeconds = 0;
    while(g_running) {
        Sleep(1000);
        counterSeconds++;
        if (counterSeconds % 60 == 0) g_logger.Heartbeat(mainTid);
        if (counterSeconds % 600 == 0) g_logger.WritePeriodicSummary();
    }
    g_logger.LogDestruction(mainTid);
}

int main(int argc, char* argv[]) {
    if (argc > 1 && strcmp(argv[1], "--install") == 0) {
        SC_HANDLE scManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (scManager) {
            char path[MAX_PATH];
            GetModuleFileNameA(NULL, path, MAX_PATH);
            CreateServiceA(scManager, "FTPSyncService", "FTP Sync Service", SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, path, NULL, NULL, NULL, NULL, NULL);
            CloseServiceHandle(scManager);
            std::cout << "Servizio installato." << std::endl;
        }
    } else {
        SERVICE_TABLE_ENTRY ServiceTable[] = {{(LPSTR)"FTPSyncService", (LPSERVICE_MAIN_FUNCTION)ServiceMain}, {NULL, NULL}};
        StartServiceCtrlDispatcher(ServiceTable);
    }
    return 0;
}