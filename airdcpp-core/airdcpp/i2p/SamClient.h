/*
 * Copyright (C) 2026 AirDC-I2P contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef DCPLUSPLUS_DCPP_I2P_SAM_CLIENT_H
#define DCPLUSPLUS_DCPP_I2P_SAM_CLIENT_H

#include <airdcpp/core/classes/Exception.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

#ifdef _WIN32
#include <airdcpp/core/header/w.h>
#else
#include <sys/socket.h>
#endif

namespace dcpp::i2p {

class SamException : public Exception {
public:
	explicit SamException(const std::string& aError) : Exception(aError) { }
	~SamException() noexcept override = default;
};

/**
 * SAM is intentionally restricted to a numeric loopback address. This avoids
 * ordinary name resolution and keeps the application-to-router hop local.
 */
struct SamEndpoint {
	std::string host = "127.0.0.1";
	uint16_t port = 7656;

	bool isLoopback() const noexcept;
	void validate() const;
	std::string toString() const;
};

struct SamReply {
	std::string command;
	std::string subcommand;
	std::map<std::string, std::string> options;

	std::optional<std::string> get(const std::string& aKey) const;
};

SamReply parseSamReply(std::string_view aLine);
bool isI2PDestination(const std::string& aDestination) noexcept;
std::string destinationToB32(const std::string& aPublicDestination);

class SamSocket {
public:
	SamSocket() noexcept;
	~SamSocket() noexcept;

	SamSocket(SamSocket&& rhs) noexcept;
	SamSocket& operator=(SamSocket&& rhs) noexcept;

	SamSocket(const SamSocket&) = delete;
	SamSocket& operator=(const SamSocket&) = delete;

	static SamSocket connect(const SamEndpoint& aEndpoint, std::chrono::milliseconds aTimeout);

	bool isOpen() const noexcept;
	void close() noexcept;

	void write(std::string_view aData, std::chrono::milliseconds aTimeout);
	void writeLine(std::string_view aLine, std::chrono::milliseconds aTimeout);
	std::string readLine(std::chrono::milliseconds aTimeout, size_t aMaximumLength = 64 * 1024);
	size_t read(void* aBuffer, size_t aLength, std::chrono::milliseconds aTimeout);

private:
#ifdef _WIN32
	using Handle = SOCKET;
	static constexpr Handle INVALID_HANDLE = INVALID_SOCKET;
#else
	using Handle = int;
	static constexpr Handle INVALID_HANDLE = -1;
#endif

	explicit SamSocket(Handle aHandle) noexcept;

	Handle handle;

	static void initializePlatform();
	static void setBlocking(Handle aHandle, bool aBlocking);
	static void waitFor(Handle aHandle, bool aRead, bool aWrite, std::chrono::milliseconds aTimeout);
	static int getLastError() noexcept;
	static void closeHandle(Handle aHandle) noexcept;
};

struct SamIdentity {
	std::string publicDestination;
	std::string b32Address;
};

class SamIdentityStore {
public:
	static std::optional<std::string> load(const std::filesystem::path& aPath);
	static void save(const std::filesystem::path& aPath, const std::string& aPrivateDestination);
};

struct SamSessionOptions {
	std::string sessionId;
	uint16_t inboundQuantity = 3;
	uint16_t outboundQuantity = 3;
	std::chrono::milliseconds handshakeTimeout { 10'000 };
	std::chrono::milliseconds sessionTimeout { 90'000 };
	std::chrono::milliseconds streamTimeout { 90'000 };
};

struct SamIncomingStream {
	std::unique_ptr<SamSocket> socket;
	std::string peerDestination;
};

/**
 * One long-lived STREAM session. Each outgoing or incoming virtual stream gets
 * its own local SAM connection while this control socket keeps the session live.
 */
class SamSession {
public:
	SamSession(SamEndpoint aEndpoint, std::filesystem::path aIdentityPath, SamSessionOptions aOptions = { });
	~SamSession() noexcept;

	SamSession(const SamSession&) = delete;
	SamSession& operator=(const SamSession&) = delete;

	void start();
	void stop() noexcept;
	bool isStarted() const noexcept;

	SamIdentity getIdentity() const;
	std::string lookup(const std::string& aName);
	std::unique_ptr<SamSocket> connect(const std::string& aDestination);
	SamIncomingStream accept();
	bool ping(const std::string& aPayload = "airdcpp-i2p");

private:
	SamEndpoint endpoint;
	std::filesystem::path identityPath;
	SamSessionOptions options;

	mutable std::mutex mutex;
	std::unique_ptr<SamSocket> controlSocket;
	SamIdentity identity;
	std::string privateDestination;
	std::string negotiatedVersion;

	static std::string generateSessionId();
	static SamReply transact(SamSocket& aSocket, std::string_view aCommand, std::chrono::milliseconds aTimeout);
	static void hello(SamSocket& aSocket, std::chrono::milliseconds aTimeout, std::string& aVersion);
	static void requireOk(const SamReply& aReply, const std::string& aCommand, const std::string& aSubcommand);

	SamSocket openSocket(std::chrono::milliseconds aTimeout) const;
	void loadOrCreateIdentity(SamSocket& aSocket);
	void createSession(SamSocket& aSocket);
	void refreshPublicDestination(SamSocket& aSocket);
};

} // namespace dcpp::i2p

#endif // DCPLUSPLUS_DCPP_I2P_SAM_CLIENT_H
