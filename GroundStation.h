/**
 * GroundStation.h
 * Ground station with ZKP verification
 */

#ifndef __DRONEAUTH_GROUNDSTATION_H_
#define __DRONEAUTH_GROUNDSTATION_H_

#include <omnetpp.h>
#include <string>
using namespace omnetpp;
#include <vector>
#include <map>
#include "inet/common/INETDefs.h"
#include "inet/applications/base/ApplicationBase.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"
#include "inet/networklayer/common/L3Address.h"
#include <set>

// Forward declaration
namespace droneauth {
    class ZKPModule;
}

class GroundStation : public inet::ApplicationBase
{
protected:
    // Parameters
    int localPort;
    
    // ZKP verifiers for each drone
    std::map<std::string, droneauth::ZKPModule*> droneVerifiers;
    
    // Pending challenges
    std::map<std::string, std::string> pendingChallenges;
    
    // Drone addresses for responses
    std::map<std::string, std::pair<inet::L3Address, int>> droneAddresses;
    
    // Network
    inet::UdpSocket socket;
    
    // Statistics
    int numAuthRequests;
    int numAuthSuccess;
    int numAuthFailures;
    
    // Signals
    omnetpp::simsignal_t authRequestSignal;
    omnetpp::simsignal_t authSuccessSignal;
    omnetpp::simsignal_t authFailureSignal;

private:
    std::set<std::string> authorizedDrones = {
        "DRONE_001", "DRONE_002", "DRONE_003", "DRONE_004", "DRONE_005"
    };

protected:
    virtual int numInitStages() const override { return inet::NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void finish() override;
    
    virtual void handleMessageWhenUp(omnetpp::cMessage *msg) override;
    
    // Message handlers
    virtual void handleAuthRequest(const std::vector<uint8_t>& data,
                                   const inet::L3Address& srcAddr, int srcPort);
    virtual void handleProof(const std::vector<uint8_t>& data,
                            const inet::L3Address& srcAddr, int srcPort);
    
    // Response messages
    virtual void sendAuthSuccess(const inet::L3Address& destAddr, int destPort);
    virtual void sendAuthFailure(const inet::L3Address& destAddr, int destPort);
    
    // Utility
    virtual void sendPacket(const std::vector<uint8_t>& data,
                           const inet::L3Address& destAddr, int destPort);
    
    // Lifecycle
    virtual void handleStartOperation(inet::LifecycleOperation *operation) override;
    virtual void handleStopOperation(inet::LifecycleOperation *operation) override;
    virtual void handleCrashOperation(inet::LifecycleOperation *operation) override;

public:
    GroundStation();
    virtual ~GroundStation();
};

#endif
