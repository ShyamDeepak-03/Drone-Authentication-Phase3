/**
 * DroneAuthApp.h
 * Drone authentication application with ZKP
 */

#ifndef __DRONEAUTH_DRONEAUTHAPP_H_
#define __DRONEAUTH_DRONEAUTHAPP_H_

#include <omnetpp.h>
#include <string>
using namespace omnetpp;
#include <vector>
#include "inet/common/INETDefs.h"
#include "inet/applications/base/ApplicationBase.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"

// Forward declaration
namespace droneauth {
    class ZKPModule;
}

class DroneAuthApp : public inet::ApplicationBase
{
protected:
    // Parameters
    int localPort;
    int destPort;
    std::string droneId;
    std::string password;
    
    // ZKP module
    droneauth::ZKPModule *zkpModule;
    
    // State
    std::string currentChallenge;
    
    // Network
    inet::UdpSocket socket;
    omnetpp::cMessage *selfMsg;
    omnetpp::cMessage *timeoutMsg;
    
    // Statistics
    int numAuthRequests;
    int numAuthSuccess;
    int numAuthFailures;
    
    // Signals
    omnetpp::simsignal_t authRequestSignal;
    omnetpp::simsignal_t authSuccessSignal;
    omnetpp::simsignal_t authFailureSignal;

protected:
    virtual int numInitStages() const override { return inet::NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void finish() override;
    
    virtual void handleMessageWhenUp(omnetpp::cMessage *msg) override;
    virtual void handleSelfMessage(omnetpp::cMessage *msg);
    virtual void handleIncomingMessage(omnetpp::cMessage *msg);
    
    // Authentication flow
    virtual void sendAuthenticationRequest();
    virtual void handleChallengeMessage(const std::vector<uint8_t>& data);
    virtual void sendZKProof();
    virtual void handleAuthSuccessMessage(const std::vector<uint8_t>& data);
    virtual void handleAuthFailureMessage(const std::vector<uint8_t>& data);
    virtual void handleAuthTimeout();
    
    // Utility
    virtual void sendPacket(const std::vector<uint8_t>& data);
    
    // Lifecycle
    virtual void handleStartOperation(inet::LifecycleOperation *operation) override;
    virtual void handleStopOperation(inet::LifecycleOperation *operation) override;
    virtual void handleCrashOperation(inet::LifecycleOperation *operation) override;

public:
    DroneAuthApp();
    virtual ~DroneAuthApp();
};

#endif
