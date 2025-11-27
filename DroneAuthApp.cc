/**
 * DroneAuthApp.cc
 * Drone authentication application with Zero-Knowledge Proof
 * FIXED: Proper timeout management and visual feedback
 */

#include "DroneAuthApp.h"
#include "ZKPModule.h"
#include <omnetpp.h>
#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/Packet.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"

using namespace inet;
using namespace omnetpp;
using namespace droneauth;

Define_Module(DroneAuthApp);

// Custom message kinds
#define MSG_SEND_AUTH_REQUEST    1
#define MSG_SEND_PROOF          2
#define MSG_AUTH_TIMEOUT        3

DroneAuthApp::DroneAuthApp() {
    selfMsg = nullptr;
    timeoutMsg = nullptr;
    zkpModule = nullptr;
}

DroneAuthApp::~DroneAuthApp() {
    cancelAndDelete(selfMsg);
    cancelAndDelete(timeoutMsg);
    if (zkpModule) {
        delete zkpModule;
    }
}

void DroneAuthApp::initialize(int stage) {
    ApplicationBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        // Read parameters
        localPort = par("localPort");
        destPort = par("destPort");
        droneId = par("droneId").stdstringValue();
        password = par("password").stdstringValue();

        // Statistics
        numAuthRequests = 0;
        numAuthSuccess = 0;
        numAuthFailures = 0;

        // Register signals
        authRequestSignal = registerSignal("authRequest");
        authSuccessSignal = registerSignal("authSuccess");
        authFailureSignal = registerSignal("authFailure");

        // Initialize ZKP module
        zkpModule = new ZKPModule(droneId);
        zkpModule->setup();
        zkpModule->initializeProver(droneId, password);
        zkpModule->createCommitment();

        EV << "Drone " << droneId << " initialized with ZKP" << endl;
        EV << "Commitment: " << ZKPModule::bytesToHex(zkpModule->getCommitment()).substr(0, 16) << "..." << endl;

        // Schedule first authentication
        selfMsg = new cMessage("sendAuthRequest");
        selfMsg->setKind(MSG_SEND_AUTH_REQUEST);
    }
}

void DroneAuthApp::finish() {
    ApplicationBase::finish();

    recordScalar("authRequests", numAuthRequests);
    recordScalar("authSuccess", numAuthSuccess);
    recordScalar("authFailures", numAuthFailures);

    if (numAuthRequests > 0) {
        double successRate = (double)numAuthSuccess / numAuthRequests * 100.0;
        recordScalar("successRate", successRate);
    }
}

void DroneAuthApp::handleMessageWhenUp(cMessage *msg) {
    if (msg->isSelfMessage()) {
        handleSelfMessage(msg);
    } else if (dynamic_cast<Packet *>(msg)) {
        handleIncomingMessage(msg);
    } else {
        EV_WARN << "Received indication message: " << msg->getName() << endl;
        delete msg;
    }
}

void DroneAuthApp::handleSelfMessage(cMessage *msg) {
    switch (msg->getKind()) {
        case MSG_SEND_AUTH_REQUEST:
            sendAuthenticationRequest();
            break;

        case MSG_SEND_PROOF:
            sendZKProof();
            break;

        case MSG_AUTH_TIMEOUT:
            handleAuthTimeout();
            break;

        default:
            throw cRuntimeError("Unknown self message kind: %d", msg->getKind());
    }
}

void DroneAuthApp::handleIncomingMessage(cMessage *msg) {
    Packet *packet = check_and_cast<Packet *>(msg);

    auto chunk = packet->peekDataAsBytes();
    std::vector<uint8_t> data(chunk->getBytes().begin(), chunk->getBytes().end());

    // Parse message type (first byte)
    if (data.size() < 1) {
        delete packet;
        return;
    }

    uint8_t msgType = data[0];

    switch (msgType) {
        case 0x02: // CHALLENGE message
            handleChallengeMessage(data);
            break;

        case 0x04: // AUTH_SUCCESS message
            handleAuthSuccessMessage(data);
            break;

        case 0x05: // AUTH_FAILURE message
            handleAuthFailureMessage(data);
            break;

        default:
            EV_WARN << "Unknown message type: " << (int)msgType << endl;
    }

    delete packet;
}

void DroneAuthApp::sendAuthenticationRequest() {
    EV << "=======================================" << endl;
    EV << "DRONE " << droneId << " sending auth request" << endl;
    EV << "=======================================" << endl;
    numAuthRequests++;
    emit(authRequestSignal, numAuthRequests);

    EV << "Sending authentication request to ground station" << endl;

    // Create message: [type(1)] [droneId_len(4)] [droneId] [commitment_len(4)] [commitment]
    std::vector<uint8_t> msgData;

    // Message type: AUTH_REQUEST
    msgData.push_back(0x01);

    // Drone ID
    uint32_t idLen = droneId.length();
    msgData.insert(msgData.end(), (uint8_t*)&idLen, (uint8_t*)&idLen + 4);
    msgData.insert(msgData.end(), droneId.begin(), droneId.end());

    // Commitment
    auto commitment = zkpModule->getCommitment();
    uint32_t commitLen = commitment.size();
    msgData.insert(msgData.end(), (uint8_t*)&commitLen, (uint8_t*)&commitLen + 4);
    msgData.insert(msgData.end(), commitment.begin(), commitment.end());

    // Send packet
    sendPacket(msgData);

    // Cancel any existing timeout before creating new one
    if (timeoutMsg != nullptr) {
        if (timeoutMsg->isScheduled()) {
            cancelEvent(timeoutMsg);
        }
        delete timeoutMsg;
        timeoutMsg = nullptr;
    }

    // Set new timeout
    timeoutMsg = new cMessage("authTimeout");
    timeoutMsg->setKind(MSG_AUTH_TIMEOUT);
    scheduleAt(simTime() + par("authTimeout").doubleValue(), timeoutMsg);
}

void DroneAuthApp::handleChallengeMessage(const std::vector<uint8_t>& data) {
    EV << "Received challenge from ground station" << endl;

    // Parse: [type(1)] [challenge_len(4)] [challenge]
    if (data.size() < 5) {
        EV_ERROR << "Invalid challenge message" << endl;
        return;
    }

    size_t offset = 1;
    uint32_t chalLen;
    std::memcpy(&chalLen, &data[offset], 4);
    offset += 4;

    if (data.size() < offset + chalLen) {
        EV_ERROR << "Challenge message too short" << endl;
        return;
    }

    std::string challenge(data.begin() + offset, data.begin() + offset + chalLen);
    currentChallenge = challenge;

    EV << "Challenge received: " << challenge << endl;

    // Schedule proof generation
    cMessage *proofMsg = new cMessage("sendProof");
    proofMsg->setKind(MSG_SEND_PROOF);
    scheduleAt(simTime() + 0.001, proofMsg); // 1ms delay
}

void DroneAuthApp::sendZKProof() {
    EV << "Generating and sending ZK proof" << endl;

    // Generate proof
    ZKProof proof = zkpModule->generateProof(currentChallenge);
    auto stats = zkpModule->getLastProofStats();

    EV << "Proof generated in " << stats.generationTime << " ms" << endl;

    // Serialize proof
    auto serializedProof = proof.serialize();

    // Create message: [type(1)] [proof_data]
    std::vector<uint8_t> msgData;
    msgData.push_back(0x03); // PROOF message type
    msgData.insert(msgData.end(), serializedProof.begin(), serializedProof.end());

    // Send packet
    sendPacket(msgData);
}

void DroneAuthApp::handleAuthSuccessMessage(const std::vector<uint8_t>& data) {
    EV << "=======================================" << endl;
    EV << "DRONE " << droneId << " RECEIVED SUCCESS!" << endl;
    EV << "=======================================" << endl;
    // Cancel pending authentication request timer
    if (selfMsg != nullptr && selfMsg->isScheduled()) {
        cancelEvent(selfMsg);
    }
    
    // Cancel authentication timeout - CRITICAL FIX
    if (timeoutMsg != nullptr) {
        if (timeoutMsg->isScheduled()) {
            cancelEvent(timeoutMsg);
        }
        delete timeoutMsg;
        timeoutMsg = nullptr;
    }
    
    numAuthSuccess++;
    emit(authSuccessSignal, numAuthSuccess);

    EV << "✓✓✓ AUTHENTICATION SUCCESSFUL! Drone " << droneId << " authenticated" << endl;

    // VISUAL FEEDBACK: Change drone to GREEN and make it BIGGER
    getParentModule()->getDisplayString().setTagArg("i", 1, "green");
    getParentModule()->getDisplayString().setTagArg("is", 0, "80");
    getParentModule()->getDisplayString().setTagArg("i", 0, "misc/drone");
    bubble("✓ AUTHENTICATED!");
    printf("\n\n=== DRONE %s TURNED GREEN ===\n\n", droneId.c_str());

    // Update app display
    getDisplayString().setTagArg("i", 1, "green");
    getDisplayString().setTagArg("t", 0, "Authenticated");
}

void DroneAuthApp::handleAuthFailureMessage(const std::vector<uint8_t>& data) {
    EV << "=======================================" << endl;
    EV << "DRONE " << droneId << " RECEIVED FAILURE!" << endl;
    EV << "=======================================" << endl;
    // Cancel authentication timeout since we got a response
    if (timeoutMsg != nullptr) {
        if (timeoutMsg->isScheduled()) {
            cancelEvent(timeoutMsg);
        }
        delete timeoutMsg;
        timeoutMsg = nullptr;
    }
    
    numAuthFailures++;
    emit(authFailureSignal, numAuthFailures);

    EV_ERROR << "✗✗✗ AUTHENTICATION FAILED for drone " << droneId << endl;

    // VISUAL FEEDBACK: Change drone to RED and make it BIGGER
    getParentModule()->getDisplayString().setTagArg("i", 1, "red");
    getParentModule()->getDisplayString().setTagArg("is", 0, "80");
    getParentModule()->getDisplayString().setTagArg("i", 0, "misc/drone");
    bubble("✗ AUTH FAILED!");
    printf("\n\n=== DRONE %s TURNED RED ===\n\n", droneId.c_str());

    // Update app display
    getDisplayString().setTagArg("i", 1, "red");
    getDisplayString().setTagArg("t", 0, "Auth Failed");
}

void DroneAuthApp::handleAuthTimeout() {
    EV_WARN << "Authentication timeout for drone " << droneId << endl;

    // Clean up the timeout message that just fired
    if (timeoutMsg != nullptr) {
        delete timeoutMsg;
        timeoutMsg = nullptr;
    }

    numAuthFailures++;
    emit(authFailureSignal, numAuthFailures);

    // VISUAL FEEDBACK: Timeout also shows as RED
    getParentModule()->getDisplayString().setTagArg("i", 1, "red");
    getParentModule()->getDisplayString().setTagArg("is", 0, "80");
    getParentModule()->getDisplayString().setTagArg("i", 0, "misc/drone");
    bubble("⏱ TIMEOUT!");
    // DISABLED: 
    // Retry after delay (only if retry is desired)
    scheduleAt(simTime() + par("retryInterval").doubleValue(), selfMsg);
}

void DroneAuthApp::sendPacket(const std::vector<uint8_t>& data) {
    // Get destination address
    L3Address destAddr = L3AddressResolver().resolve(par("destAddress").stringValue());

    // Create packet
    const auto& payload = makeShared<BytesChunk>(data);
    Packet *packet = new Packet("DroneAuthData");
    packet->insertAtBack(payload);

    // Send via UDP
    socket.sendTo(packet, destAddr, destPort);
}

void DroneAuthApp::handleStartOperation(LifecycleOperation *operation) {
    socket.setOutputGate(gate("socketOut"));
    socket.bind(localPort);

    // Start authentication after a small delay
    scheduleAt(simTime() + par("startTime").doubleValue(), selfMsg);
}

void DroneAuthApp::handleStopOperation(LifecycleOperation *operation) {
    if (selfMsg != nullptr && selfMsg->isScheduled()) {
        cancelEvent(selfMsg);
    }
    if (timeoutMsg != nullptr && timeoutMsg->isScheduled()) {
        cancelEvent(timeoutMsg);
    }
    socket.close();
}

void DroneAuthApp::handleCrashOperation(LifecycleOperation *operation) {
    if (selfMsg != nullptr && selfMsg->isScheduled()) {
        cancelEvent(selfMsg);
    }
    if (timeoutMsg != nullptr && timeoutMsg->isScheduled()) {
        cancelEvent(timeoutMsg);
    }
    socket.destroy();
}
