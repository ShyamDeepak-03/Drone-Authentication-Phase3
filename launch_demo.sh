#!/bin/bash

echo "╔═══════════════════════════════════════════════════╗"
echo "║  DroneAuth ZKP - Interactive Configuration       ║"
echo "╚═══════════════════════════════════════════════════╝"

echo ""
echo "Authorized Drone IDs: DRONE_001, DRONE_002, DRONE_003, DRONE_004, DRONE_005"
echo "Unauthorized IDs: DRONE_006, DRONE_007, DRONE_008, DRONE_009, DRONE_010"
echo ""

# Ask for number of drones
read -p "How many drones do you want to test? (1-5): " NUM_DRONES

# Validate input
if ! [[ "$NUM_DRONES" =~ ^[1-5]$ ]]; then
    echo "Invalid input. Using default: 3 drones"
    NUM_DRONES=3
fi

echo ""
echo "Enter Drone IDs (use numbers like 001, 008, etc.):"
DRONE_IDS=()
for ((i=0; i<$NUM_DRONES; i++)); do
    read -p "  Drone [$i] ID (e.g., 001 or 008): " DRONE_ID
    
    # Format as DRONE_XXX if just number given
    if [[ "$DRONE_ID" =~ ^[0-9]{3}$ ]]; then
        DRONE_ID="DRONE_$DRONE_ID"
    elif [[ ! "$DRONE_ID" =~ ^DRONE_[0-9]{3}$ ]]; then
        echo "    → Invalid format. Using DRONE_001"
        DRONE_ID="DRONE_001"
    fi
    
    echo "    → Set to: $DRONE_ID"
    DRONE_IDS+=("$DRONE_ID")
done

echo ""
echo "Generating configuration..."

# Create runtime config file
cat > omnetpp_runtime.ini << INIEOF
[General]
network = DroneAuthNetwork
ned-path = /home/opp_env/default_workspace/inet-4.5.4/src:.:src
sim-time-limit = 60s

DroneAuthNetwork.numDrones = $NUM_DRONES

*.configurator.config = xml("<config><interface hosts='**' address='10.0.0.x' netmask='255.255.255.0'/></config>")

# ============================================
# WIRELESS CONFIGURATION
# ============================================

*.radioMedium.typename = "Ieee80211ScalarRadioMedium"
*.radioMedium.backgroundNoise.power = -90dBm

**.numWlanInterfaces = 1
**.numEthInterfaces = 0

**.wlan[*].typename = "Ieee80211Interface"
**.wlan[*].radio.typename = "Ieee80211ScalarRadio"
**.wlan[*].radio.bandName = "2.4 GHz"
**.wlan[*].radio.channelNumber = 6

**.wlan[*].mac.typename = "Ieee80211Mac"
**.wlan[*].mac.dcf.channelAccess.cwMin = 15
**.wlan[*].mac.dcf.channelAccess.cwMax = 1023

# Disable WiFi scanning - use ad-hoc
**.wlan[*].agent.typename = ""
**.wlan[*].mgmt.typename = "Ieee80211MgmtAdhoc"

*.groundStation.wlan[*].radio.transmitter.power = 100mW
*.groundStation.wlan[*].radio.receiver.sensitivity = -85dBm
*.drone[*].wlan[*].radio.transmitter.power = 100mW
*.drone[*].wlan[*].radio.receiver.sensitivity = -85dBm

# GlobalArp for instant resolution
**.arp.typename = "GlobalArp"

# ============================================
# MOBILITY - CRITICAL FIX
# ============================================

**.mobility.initFromDisplayString = false

*.groundStation.mobility.typename = "StationaryMobility"
*.groundStation.mobility.initialX = 700m
*.groundStation.mobility.initialY = 700m
*.groundStation.mobility.initialZ = 10m

*.drone[*].mobility.typename = "StationaryMobility"

INIEOF

# Add mobility for each drone
X_POS=600
Y_POS=650
for ((i=0; i<$NUM_DRONES; i++)); do
    cat >> omnetpp_runtime.ini << INIEOF
*.drone[$i].mobility.initialX = ${X_POS}m
*.drone[$i].mobility.initialY = ${Y_POS}m
*.drone[$i].mobility.initialZ = 100m
INIEOF
    X_POS=$((X_POS + 100))
    if [ $((i % 2)) -eq 0 ]; then
        Y_POS=600
    else
        Y_POS=650
    fi
done

# Add app configuration
cat >> omnetpp_runtime.ini << INIEOF

# ============================================
# APPLICATION CONFIGURATION
# ============================================

*.groundStation.numApps = 1
*.groundStation.app[0].typename = "GroundStation"
*.groundStation.app[0].localPort = 5000

*.drone[*].numApps = 1
*.drone[*].app[0].typename = "DroneAuthApp"
*.drone[*].app[0].password = "secure"
*.drone[*].app[0].localPort = 6000
*.drone[*].app[0].destPort = 5000
*.drone[*].app[0].destAddress = "groundStation"

INIEOF

# Add start times with proper spacing (5 seconds apart)
START_TIME=3
for ((i=0; i<$NUM_DRONES; i++)); do
    echo "*.drone[$i].app[0].startTime = ${START_TIME}.0s" >> omnetpp_runtime.ini
    START_TIME=$((START_TIME + 5))
done

# Add timeouts
cat >> omnetpp_runtime.ini << INIEOF

*.drone[*].app[0].authTimeout = 999999s
*.drone[*].app[0].retryInterval = 999999s

# Drone IDs
INIEOF

# Add drone IDs
for ((i=0; i<$NUM_DRONES; i++)); do
    echo "*.drone[$i].app[0].droneId = \"${DRONE_IDS[$i]}\"" >> omnetpp_runtime.ini
done

# Add logging
cat >> omnetpp_runtime.ini << INIEOF

# ============================================
# LOGGING
# ============================================
**.cmdenv-log-level = info
**.app[*].cmdenv-log-level = info
INIEOF

echo "✓ Configuration created with $NUM_DRONES drones!"
echo ""
echo "Drone Configuration:"
for ((i=0; i<$NUM_DRONES; i++)); do
    ID="${DRONE_IDS[$i]}"
    if [[ "$ID" =~ DRONE_00[1-5]$ ]]; then
        echo "  drone[$i] = $ID ✓ AUTHORIZED (will be GREEN)"
    else
        echo "  drone[$i] = $ID ✗ UNAUTHORIZED (will be RED)"
    fi
done

echo ""
echo "Press Enter to launch OMNeT++ GUI..."
read

# Launch OMNeT++ with custom config
./out/clang-release/DroneAuth -u Qtenv -f omnetpp_runtime.ini
