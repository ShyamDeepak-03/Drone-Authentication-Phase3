/**
 * ZKPModule.h
 * Zero-Knowledge Proof module for drone authentication in OMNeT++
 */

#ifndef ZKPMODULE_H_
#define ZKPMODULE_H_

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <openssl/sha.h>
#include <openssl/rand.h>

namespace droneauth {

struct ZKProof {
    std::vector<uint8_t> proofData;
    std::vector<uint8_t> commitment;
    std::string challenge;
    uint64_t timestamp;
    
    ZKProof() : timestamp(0) {}
    std::vector<uint8_t> serialize() const;
    static ZKProof deserialize(const std::vector<uint8_t>& data);
};

class ZKPModule {
private:
    std::vector<uint8_t> privateSecret;
    std::vector<uint8_t> publicCommitment;
    std::string droneId;
    std::vector<uint8_t> sessionNonce;
    std::vector<uint8_t> provingKey;
    std::vector<uint8_t> verificationKey;
    
    std::vector<uint8_t> sha256Hash(const std::vector<uint8_t>& data) const;
    std::vector<uint8_t> generateRandomBytes(size_t length) const;
    std::vector<uint8_t> combineVectors(const std::vector<std::vector<uint8_t>>& vectors) const;

public:
    ZKPModule();
    explicit ZKPModule(const std::string& id);
    ~ZKPModule();
    
    void setup();
    void generateKeys();
    void initializeProver(const std::string& id, const std::string& password = "");
    void createCommitment();
    ZKProof generateProof(const std::string& challenge);
    std::vector<uint8_t> getCommitment() const;
    
    void initializeVerifier(const std::vector<uint8_t>& commitment, const std::string& droneId);
    std::string generateChallenge();
    bool verifyProof(const ZKProof& proof);
    
    bool isProverInitialized() const;
    bool isVerifierInitialized() const;
    std::string getDroneId() const;
    void reset();
    
    static std::string bytesToHex(const std::vector<uint8_t>& bytes);
    
    struct ProofStats {
        size_t proofSize;
        size_t commitmentSize;
        double generationTime;
        double verificationTime;
    };
    ProofStats getLastProofStats() const;

private:
    ProofStats lastStats;
    bool proverInitialized;
    bool verifierInitialized;
    bool keysGenerated;
    std::string lastChallenge;
};

} // namespace droneauth

#endif /* ZKPMODULE_H_ */
