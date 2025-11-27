/**
 * GroundStation.cc
 * Ground station with Zero-Knowledge Proof verification
 */
#include "GroundStation.h"
#include "ZKPModule.h"
#include <omnetpp.h>
#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/Packet.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/transportlayer/common/L4PortTag_m.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"
#include <set>
#include <cstdio>
using namespace inet;
using namespace omnetpp;
using namespace droneauth;
Define_Module(GroundStation);
GroundStation::GroundStation() {
    authorizedDrones = {
        "DRONE_001",
        "DRONE_002",
        "DRONE_003",
        "DRONE_004",
        "DRONE_005"
    };
}
GroundStation::~GroundStation() {
    // Clean up drone verifiers
    for (auto& pair : droneVerifiers) {
        delete pair.second;
    }
    droneVerifiers.clear();
}
void GroundStation::initialize(int stage) {
    ApplicationBase::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        localPort = par("localPort");
        // Statistics
        numAuthRequests = 0;
        numAuthSuccess = 0;
        numAuthFailures = 0;
        // Register signals
        authRequestSignal = registerSignal("authRequest");
        authSuccessSignal = registerSignal("authSuccess");
        authFailureSignal = registerSignal("authFailure");
        EV << "Ground Station initialized" << endl;
    }
}
void GroundStation::finish() {
    ApplicationBase::finish();
    recordScalar("totalAuthRequests", numAuthRequests);
    recordScalar("totalAuthSuccess", numAuthSuccess);
    recordScalar("totalAuthFailures", numAuthFailures);
    if (numAuthRequests > 0) {
        double successRate = (double)numAuthSuccess / numAuthRequests * 100.0;
        recordScalar("successRate", successRate);
    }
}
void GroundStation::handleMessageWhenUp(cMessage *msg) {
    if (dynamic_cast<Packet *>(msg)) {
        Packet *packet = check_and_cast<Packet *>(msg);
        auto chunk = packet->peekDataAsBytes();
        std::vector<uint8_t> data(chunk->getBytes().begin(), chunk->getBytes().end());
        auto srcAddr = packet->getTag<inet::L3AddressInd>()->getSrcAddress();
        auto srcPort = packet->getTag<inet::L4PortInd>()->getSrcPort();
        if (data.size() < 1) {
            delete packet;
            return;
        }
        uint8_t msgType = data[0];
        switch (msgType) {
            case 0x01:
                handleAuthRequest(data, srcAddr, srcPort);
                break;
            case 0x03:
                handleProof(data, srcAddr, srcPort);
                break;
            default:
                EV_WARN << "Unknown message type: " << (int)msgType << endl;
        }
        delete packet;
    } else {
        EV_WARN << "Received indication message: " << msg->getName() << endl;
        delete msg;
    }
}
void GroundStation::handleAuthRequest(const std::vector<uint8_t>& data,
                                      const L3Address& srcAddr, int srcPort) {
    numAuthRequests++;
    emit(authRequestSignal, numAuthRequests);
   
    EV << "Received authentication request" << endl;
   
    // Parse: [type(1)] [droneId_len(4)] [droneId] [commitment_len(4)] [commitment]
    if (data.size() < 9) {
        EV_ERROR << "Invalid auth request message" << endl;
        sendAuthFailure(srcAddr, srcPort);
        return;
    }
    size_t offset = 1;
    // Parse drone ID
    uint32_t idLen;
    std::memcpy(&idLen, &data[offset], 4);
    offset += 4;
    if (data.size() < offset + idLen + 4) {
        EV_ERROR << "Auth request message too short" << endl;
        sendAuthFailure(srcAddr, srcPort);
        return;
    }
    std::string droneId(data.begin() + offset, data.begin() + offset + idLen);
   
    // CHECK IF DRONE IS AUTHORIZED
    if (authorizedDrones.find(droneId) == authorizedDrones.end()) {
        EV << "✗✗✗ UNAUTHORIZED DRONE: " << droneId << " - Rejecting!" << endl;
        printf("✗✗✗ UNAUTHORIZED DRONE: %s - Authentication REJECTED!\n", droneId.c_str());
        sendAuthFailure(srcAddr, srcPort);
        numAuthFailures++;
        emit(authFailureSignal, numAuthFailures);
        return;
    }
   
    EV << "✓ Drone " << droneId << " is in authorized list" << endl;
   
    offset += idLen;
    // Parse commitment
    uint32_t commitLen;
    std::memcpy(&commitLen, &data[offset], 4);
    offset += 4;
    if (data.size() < offset + commitLen) {
        EV_ERROR << "Invalid commitment in auth request" << endl;
        sendAuthFailure(srcAddr, srcPort);
        return;
    }
    std::vector<uint8_t> commitment(data.begin() + offset, data.begin() + offset + commitLen);
    EV << "Auth request from drone: " << droneId << endl;
    EV << "Commitment: " << ZKPModule::bytesToHex(commitment).substr(0, 16) << "..." << endl;
    // Create or get verifier for this drone
    ZKPModule *verifier = nullptr;
    auto it = droneVerifiers.find(droneId);
    if (it == droneVerifiers.end()) {
        // New drone - create verifier
        verifier = new ZKPModule();
        verifier->setup();
        verifier->initializeVerifier(commitment, droneId);
        droneVerifiers[droneId] = verifier;
        EV << "Registered new drone: " << droneId << endl;
    } else {
        verifier = it->second;
    }
    // Generate challenge
    std::string challenge = verifier->generateChallenge();
    pendingChallenges[droneId] = challenge;
    droneAddresses[droneId] = std::make_pair(srcAddr, srcPort);
    EV << "Sending challenge: " << challenge << endl;
    // Send challenge message: [type(1)] [challenge_len(4)] [challenge]
    std::vector<uint8_t> msgData;
    msgData.push_back(0x02); // CHALLENGE type
    uint32_t chalLen = challenge.length();
    msgData.insert(msgData.end(), (uint8_t*)&chalLen, (uint8_t*)&chalLen + 4);
    msgData.insert(msgData.end(), challenge.begin(), challenge.end());
    sendPacket(msgData, srcAddr, srcPort);
}
void GroundStation::handleProof(const std::vector<uint8_t>& data,
                                const L3Address& srcAddr, int srcPort) {
    EV << "Received proof from drone" << endl;
    // Parse: [type(1)] [proof_data]
    if (data.size() < 2) {
        EV_ERROR << "Invalid proof message" << endl;
        sendAuthFailure(srcAddr, srcPort);
        return;
    }
    // Deserialize proof
    std::vector<uint8_t> proofData(data.begin() + 1, data.end());
    ZKProof proof;
    try {
        proof = ZKProof::deserialize(proofData);
    } catch (const std::exception& e) {
        EV_ERROR << "Failed to deserialize proof: " << e.what() << endl;
        sendAuthFailure(srcAddr, srcPort);
        return;
    }
    // Find drone ID from challenge
    std::string droneId;
    for (const auto& pair : pendingChallenges) {
        if (pair.second == proof.challenge) {
            droneId = pair.first;
            break;
        }
    }
    if (droneId.empty()) {
        EV_ERROR << "Unknown challenge in proof" << endl;
        sendAuthFailure(srcAddr, srcPort);
        return;
    }
    // Get verifier
    auto it = droneVerifiers.find(droneId);
    if (it == droneVerifiers.end()) {
        EV_ERROR << "No verifier found for drone: " << droneId << endl;
        sendAuthFailure(srcAddr, srcPort);
        return;
    }
    ZKPModule *verifier = it->second;
    // Verify proof
    bool isValid = verifier->verifyProof(proof);
    auto stats = verifier->getLastProofStats();
    EV << "Proof verification completed in " << stats.verificationTime << " ms" << endl;
    if (isValid) {
        numAuthSuccess++;
        emit(authSuccessSignal, numAuthSuccess);
        EV << "✓✓✓ Drone " << droneId << " AUTHENTICATED successfully!" << endl;
        sendAuthSuccess(srcAddr, srcPort);
        // Clean up
        pendingChallenges.erase(droneId);
    } else {
        numAuthFailures++;
        emit(authFailureSignal, numAuthFailures);
        EV_ERROR << "✗✗✗ Authentication FAILED for drone " << droneId << endl;
        sendAuthFailure(srcAddr, srcPort);
    }
}
void GroundStation::sendAuthSuccess(const L3Address& destAddr, int destPort) {
    std::vector<uint8_t> msgData;
    msgData.push_back(0x04); // AUTH_SUCCESS type
    sendPacket(msgData, destAddr, destPort);
}
void GroundStation::sendAuthFailure(const L3Address& destAddr, int destPort) {
    std::vector<uint8_t> msgData;
    msgData.push_back(0x05); // AUTH_FAILURE type
    sendPacket(msgData, destAddr, destPort);
}
void GroundStation::sendPacket(const std::vector<uint8_t>& data,
                               const L3Address& destAddr, int destPort) {
    const auto& payload = makeShared<BytesChunk>(data);
    Packet *packet = new Packet("GroundStationData");
    packet->insertAtBack(payload);
    socket.sendTo(packet, destAddr, destPort);
}
void GroundStation::handleStartOperation(LifecycleOperation *operation) {
    socket.setOutputGate(gate("socketOut"));
    socket.bind(localPort);
    EV << "Ground Station started on port " << localPort << endl;
}
void GroundStation::handleStopOperation(LifecycleOperation *operation) {
    socket.close();
}
void GroundStation::handleCrashOperation(LifecycleOperation *operation) {
    socket.destroy();
}
