/**
 * ZKPModule.cc
 */

#include "ZKPModule.h"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <chrono>
#include <stdexcept>

namespace droneauth {

std::vector<uint8_t> ZKProof::serialize() const {
    std::vector<uint8_t> result;
    uint32_t proofSize = proofData.size();
    result.insert(result.end(), (uint8_t*)&proofSize, (uint8_t*)&proofSize + 4);
    result.insert(result.end(), proofData.begin(), proofData.end());
    
    uint32_t commitSize = commitment.size();
    result.insert(result.end(), (uint8_t*)&commitSize, (uint8_t*)&commitSize + 4);
    result.insert(result.end(), commitment.begin(), commitment.end());
    
    uint32_t chalLen = challenge.length();
    result.insert(result.end(), (uint8_t*)&chalLen, (uint8_t*)&chalLen + 4);
    result.insert(result.end(), challenge.begin(), challenge.end());
    
    result.insert(result.end(), (uint8_t*)&timestamp, (uint8_t*)&timestamp + 8);
    return result;
}

ZKProof ZKProof::deserialize(const std::vector<uint8_t>& data) {
    ZKProof proof;
    size_t offset = 0;
    
    uint32_t proofSize;
    std::memcpy(&proofSize, &data[offset], 4);
    offset += 4;
    proof.proofData.assign(data.begin() + offset, data.begin() + offset + proofSize);
    offset += proofSize;
    
    uint32_t commitSize;
    std::memcpy(&commitSize, &data[offset], 4);
    offset += 4;
    proof.commitment.assign(data.begin() + offset, data.begin() + offset + commitSize);
    offset += commitSize;
    
    uint32_t chalLen;
    std::memcpy(&chalLen, &data[offset], 4);
    offset += 4;
    proof.challenge.assign(data.begin() + offset, data.begin() + offset + chalLen);
    offset += chalLen;
    
    std::memcpy(&proof.timestamp, &data[offset], 8);
    return proof;
}

ZKPModule::ZKPModule() 
    : proverInitialized(false), verifierInitialized(false), keysGenerated(false) {
    lastStats = ProofStats{0, 0, 0.0, 0.0};
}

ZKPModule::ZKPModule(const std::string& id) : ZKPModule() {
    droneId = id;
}

ZKPModule::~ZKPModule() {
    std::fill(privateSecret.begin(), privateSecret.end(), 0);
}

std::vector<uint8_t> ZKPModule::sha256Hash(const std::vector<uint8_t>& data) const {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

std::vector<uint8_t> ZKPModule::generateRandomBytes(size_t length) const {
    std::vector<uint8_t> bytes(length);
    RAND_bytes(bytes.data(), length);
    return bytes;
}

std::vector<uint8_t> ZKPModule::combineVectors(const std::vector<std::vector<uint8_t>>& vectors) const {
    std::vector<uint8_t> result;
    for (const auto& vec : vectors) {
        result.insert(result.end(), vec.begin(), vec.end());
    }
    return result;
}

void ZKPModule::setup() {
    generateKeys();
}

void ZKPModule::generateKeys() {
    provingKey = generateRandomBytes(64);
    verificationKey = generateRandomBytes(64);
    keysGenerated = true;
}

void ZKPModule::initializeProver(const std::string& id, const std::string& password) {
    droneId = id;
    std::vector<uint8_t> idBytes(id.begin(), id.end());
    std::vector<uint8_t> pwBytes(password.begin(), password.end());
    std::vector<uint8_t> nonce = generateRandomBytes(32);
    
    std::vector<uint8_t> combined = combineVectors({idBytes, pwBytes, nonce});
    privateSecret = sha256Hash(combined);
    sessionNonce = nonce;
    proverInitialized = true;
}

void ZKPModule::createCommitment() {
    if (!proverInitialized) {
        throw std::runtime_error("Prover not initialized");
    }
    std::vector<uint8_t> commitmentInput = combineVectors({privateSecret, sessionNonce});
    publicCommitment = sha256Hash(commitmentInput);
}

ZKProof ZKPModule::generateProof(const std::string& challenge) {
    auto startTime = std::chrono::high_resolution_clock::now();
    
    if (!proverInitialized) {
        throw std::runtime_error("Prover not initialized");
    }
    
    ZKProof proof;
    proof.challenge = challenge;
    proof.commitment = publicCommitment;
    proof.timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    
    std::vector<uint8_t> challengeBytes(challenge.begin(), challenge.end());
    std::vector<uint8_t> proofInput = combineVectors({privateSecret, challengeBytes, sessionNonce});
    proof.proofData = sha256Hash(proofInput);
    
    auto endTime = std::chrono::high_resolution_clock::now();
    lastStats.generationTime = std::chrono::duration<double, std::milli>(endTime - startTime).count();
    lastStats.proofSize = proof.proofData.size();
    lastStats.commitmentSize = proof.commitment.size();
    
    return proof;
}

std::vector<uint8_t> ZKPModule::getCommitment() const {
    return publicCommitment;
}

void ZKPModule::initializeVerifier(const std::vector<uint8_t>& commitment, const std::string& id) {
    publicCommitment = commitment;
    droneId = id;
    verifierInitialized = true;
}

std::string ZKPModule::generateChallenge() {
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    auto randomBytes = generateRandomBytes(16);
    
    std::stringstream ss;
    ss << "CHALLENGE_" << now << "_";
    ss << bytesToHex(randomBytes).substr(0, 16);
    
    lastChallenge = ss.str();
    return lastChallenge;
}

bool ZKPModule::verifyProof(const ZKProof& proof) {
    auto startTime = std::chrono::high_resolution_clock::now();
    
    if (!verifierInitialized) {
        throw std::runtime_error("Verifier not initialized");
    }
    
    if (proof.proofData.size() != SHA256_DIGEST_LENGTH) {
        return false;
    }
    
    if (proof.commitment != publicCommitment) {
        return false;
    }
    
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    int64_t timeDiff = std::abs((int64_t)now - (int64_t)proof.timestamp);
    if (timeDiff > 5000000000LL) {
        return false;
    }
    
    auto endTime = std::chrono::high_resolution_clock::now();
    lastStats.verificationTime = std::chrono::duration<double, std::milli>(endTime - startTime).count();
    
    return true;
}

bool ZKPModule::isProverInitialized() const { return proverInitialized; }
bool ZKPModule::isVerifierInitialized() const { return verifierInitialized; }
std::string ZKPModule::getDroneId() const { return droneId; }

void ZKPModule::reset() {
    privateSecret.clear();
    publicCommitment.clear();
    sessionNonce.clear();
    lastChallenge.clear();
    proverInitialized = false;
    verifierInitialized = false;
}

std::string ZKPModule::bytesToHex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : bytes) {
        ss << std::setw(2) << (int)b;
    }
    return ss.str();
}

ZKPModule::ProofStats ZKPModule::getLastProofStats() const {
    return lastStats;
}

} // namespace droneauth
