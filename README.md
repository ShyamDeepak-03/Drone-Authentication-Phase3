# DroneAuth - Zero-Knowledge Proof Based Drone Authentication

## Overview
A wireless drone authentication system using Zero-Knowledge Proofs (ZKP) for secure authentication without revealing passwords.

## Features
- **Zero-Knowledge Proof**: Drones prove they know the password without transmitting it
- **Wireless Communication**: IEEE 802.11g ad-hoc mode
- **Visual Feedback**: Authorized drones turn GREEN, unauthorized turn RED
- **Interactive Configuration**: Runtime input for number of drones and IDs
- **Collision Prevention**: Staggered authentication timing

## Requirements
- OMNeT++ 6.2.0
- INET Framework 4.5.4

## Build Instructions
```bash
make clean
make MODE=release
```

## Running Simulations

### Interactive Mode (Runtime Input)
```bash
./launch_demo.sh
```

### GUI Mode
```bash
./out/clang-release/DroneAuth -u Qtenv
```

### Command Line Mode
```bash
./out/clang-release/DroneAuth -u Cmdenv
```

## Configuration

### Authorized Drones (have correct password)
- DRONE_001 to DRONE_005

### Unauthorized Drones (wrong password)
- DRONE_006 to DRONE_010

## Network Configuration
- **Protocol**: UDP over IEEE 802.11g wireless
- **Ground Station**: 10.0.0.1 (100mW transmit power)
- **Drones**: 10.0.0.x (100mW transmit power)
- **Ad-hoc Mode**: Direct drone-to-ground station communication

## Project Structure
```
DroneAuth/
├── src/
│   ├── DroneAuthApp.cc/h      # Drone authentication application
│   ├── GroundStation.cc/h     # Ground station verification
│   ├── ZKPModule.cc/h         # Zero-Knowledge Proof implementation
│   ├── DroneAuthApp.ned       # Drone module definition
│   └── GroundStation.ned      # Ground station module definition
├── DroneAuth.ned              # Network topology
├── omnetpp.ini                # Simulation configuration
├── Makefile                   # Build configuration
└── launch_demo.sh             # Interactive launcher
```

## How It Works
1. Drone sends authentication request with commitment
2. Ground station sends challenge
3. Drone generates ZKP proof
4. Ground station verifies proof
5. Authentication success/failure with visual feedback


## Authors
Shyam Deepak
