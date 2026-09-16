/*
 * Copyright (C) 2026 AirDC-I2P contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

#include "stdinc.h"
#include <airdcpp/i2p/SamClient.h>

#include <airdcpp/hash/value/Encoder.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <algorithm>
#include <charconv>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>
#include <sstream>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace dcpp::i2p {

namespace {

constexpr size_t MINIMUM_PUBLIC_DESTINATION_LENGTH = 516;
constexpr size_t MAXIMUM_IDENTITY_FILE_LENGTH = 16 * 1024;

bool isWhitespace(char aChar) noexcept {
	return aChar == ' ' || aChar == '\t';
}

bool containsLineBreak(std::string_view aValue) noexcept {
	return aValue.find_first_of("\r\n") != std::string_view::npos;
}

std::string trimLineEndings(std::string aValue) {
	while (!aValue.empty() && (aValue.back() == '\r' || aValue.back() == '\n' || aValue.back() == ' ' || aValue.back() == '\t')) {
		aValue.pop_back();
	}

	size_t first = 0;
	while (first < aValue.size() && isWhitespace(aValue[first])) {
		++first;
	}

	return aValue.substr(first);
}

std::vector<std::string> tokenize(std::string_view aLine) {
	std::vector<std::string> tokens;
	std::string token;
	bool quoted = false;
	bool escaped = false;

	for (const auto ch : aLine) {
		if (escaped) {
			token += ch;
			escaped = false;
			continue;
		}

		if (quoted && ch == '\\') {
			escaped = true;
			continue;
		}

		if (ch == '"') {
			quoted = !quoted;
			continue;
		}

		if (!quoted && isWhitespace(ch)) {
			if (!token.empty()) {
				tokens.push_back(std::move(token));
				token.clear();
			}
			continue;
		}

		token += ch;
	}

	if (quoted || escaped) {
		throw SamException("Malformed SAM response");
	}

	if (!token.empty()) {
		tokens.push_back(std::move(token));
	}

	return tokens;
}

std::string safeMessage(const SamReply& aReply) {
	auto message = aReply.get("MESSAGE");
	if (!message || message->empty()) {
		return "SAM bridge rejected the request";
	}

	std::string result;
	result.reserve(std::min<size_t>(message->size(), 256));
	for (const auto ch : *message) {
		if (ch >= 0x20 && ch != 0x7f && result.size() < 256) {
			result += ch;
		}
	}

	return result.empty() ? "SAM bridge rejected the request" : result;
}

bool isBase64Character(char aChar) noexcept {
	return (aChar >= 'A' && aChar <= 'Z') ||
		(aChar >= 'a' && aChar <= 'z') ||
		(aChar >= '0' && aChar <= '9') ||
		aChar == '+' || aChar == '/' || aChar == '-' || aChar == '~' || aChar == '=';
}

std::vector<uint8_t> decodeI2PBase64(const std::string& aValue) {
	if (aValue.size() < MINIMUM_PUBLIC_DESTINATION_LENGTH) {
		throw SamException("I2P destination is too short");
	}

	std::string normalized;
	normalized.reserve(aValue.size() + 3);
	for (const auto ch : aValue) {
		if (!isBase64Character(ch)) {
			throw SamException("I2P destination contains invalid base64 data");
		}

		normalized += ch == '-' ? '+' : (ch == '~' ? '/' : ch);
	}

	while (normalized.size() % 4 != 0) {
		normalized += '=';
	}

	std::vector<uint8_t> decoded((normalized.size() / 4) * 3);
	auto decodedLength = EVP_DecodeBlock(decoded.data(), reinterpret_cast<const unsigned char*>(normalized.data()), static_cast<int>(normalized.size()));
	if (decodedLength < 0) {
		throw SamException("I2P destination contains invalid base64 data");
	}

	for (auto i = normalized.rbegin(); i != normalized.rend() && *i == '='; ++i) {
		--decodedLength;
	}

	if (decodedLength < 0) {
		throw SamException("I2P destination contains invalid base64 padding");
	}

	decoded.resize(static_cast<size_t>(decodedLength));
	return decoded;
}

std::string toLowerAscii(std::string aValue) {
	for (auto& ch : aValue) {
		ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
	}

	return aValue;
}

bool versionAtLeast(const std::string& aVersion, int aMajor, int aMinor) noexcept {
	auto separator = aVersion.find('.');
	if (separator == std::string::npos) {
		return false;
	}

	int major = 0;
	int minor = 0;
	auto majorResult = std::from_chars(aVersion.data(), aVersion.data() + separator, major);
	auto minorResult = std::from_chars(aVersion.data() + separator + 1, aVersion.data() + aVersion.size(), minor);
	if (majorResult.ec != std::errc() || minorResult.ec != std::errc()) {
		return false;
	}

	return major > aMajor || (major == aMajor && minor >= aMinor);
}

std::string randomHex(size_t aBytes) {
	std::vector<uint8_t> bytes(aBytes);
	if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
		throw SamException("Unable to generate a secure I2P session identifier");
	}

	constexpr char HEX[] = "0123456789abcdef";
	std::string result;
	result.reserve(bytes.size() * 2);
	for (const auto byte : bytes) {
		result += HEX[byte >> 4];
		result += HEX[byte & 0x0f];
	}

	return result;
}

bool isConnectInProgress(int aError) noexcept {
#ifdef _WIN32
	return aError == WSAEWOULDBLOCK || aError == WSAEINPROGRESS;
#else
	return aError == EINPROGRESS || aError == EWOULDBLOCK || aError == EAGAIN;
#endif
}

bool isValidSessionId(std::string_view aSessionId) noexcept {
	if (aSessionId.empty() || aSessionId.size() > 128) {
		return false;
	}

	return std::all_of(aSessionId.begin(), aSessionId.end(), [](const auto ch) {
		return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.';
	});
}

} // namespace

bool SamEndpoint::isLoopback() const noexcept {
	return host == "127.0.0.1" || host == "::1";
}

void SamEndpoint::validate() const {
	if (!isLoopback()) {
		throw SamException("SAM must use a numeric loopback address; hostnames and remote addresses are disabled");
	}

	if (port == 0) {
		throw SamException("SAM port must be nonzero");
	}
}

std::string SamEndpoint::toString() const {
	return host == "::1" ? "[::1]:" + std::to_string(port) : host + ":" + std::to_string(port);
}

std::optional<std::string> SamReply::get(const std::string& aKey) const {
	auto i = options.find(aKey);
	return i == options.end() ? std::nullopt : std::optional<std::string>(i->second);
}

SamReply parseSamReply(std::string_view aLine) {
	if (containsLineBreak(aLine)) {
		throw SamException("SAM response contains an unexpected line break");
	}

	auto tokens = tokenize(aLine);
	if (tokens.empty()) {
		throw SamException("Empty SAM response");
	}

	SamReply reply;
	reply.command = std::move(tokens.front());
	size_t optionStart = 1;
	if (tokens.size() > 1 && tokens[1].find('=') == std::string::npos) {
		reply.subcommand = std::move(tokens[1]);
		optionStart = 2;
	}

	for (size_t i = optionStart; i < tokens.size(); ++i) {
		auto separator = tokens[i].find('=');
		if (separator == std::string::npos) {
			if (!reply.options.emplace(tokens[i], std::string()).second) {
				throw SamException("Duplicate SAM response option");
			}
		} else if (separator != 0) {
			if (!reply.options.emplace(tokens[i].substr(0, separator), tokens[i].substr(separator + 1)).second) {
				throw SamException("Duplicate SAM response option");
			}
		} else {
			throw SamException("Malformed SAM response option");
		}
	}

	return reply;
}

bool isI2PDestination(const std::string& aDestination) noexcept {
	if (aDestination.empty() || containsLineBreak(aDestination)) {
		return false;
	}

	auto lower = toLowerAscii(aDestination);
	constexpr std::string_view B32_SUFFIX = ".b32.i2p";
	if (lower.ends_with(B32_SUFFIX)) {
		auto labelLength = lower.size() - B32_SUFFIX.size();
		if (labelLength != 52) {
			return false;
		}

		for (size_t i = 0; i < labelLength; ++i) {
			const auto ch = lower[i];
			if (!((ch >= 'a' && ch <= 'z') || (ch >= '2' && ch <= '7'))) {
				return false;
			}
		}

		return true;
	}

	if (aDestination.size() < MINIMUM_PUBLIC_DESTINATION_LENGTH) {
		return false;
	}

	return std::all_of(aDestination.begin(), aDestination.end(), isBase64Character);
}

std::string destinationToB32(const std::string& aPublicDestination) {
	auto destination = decodeI2PBase64(aPublicDestination);
	std::array<uint8_t, EVP_MAX_MD_SIZE> digest { };
	unsigned int digestLength = 0;
	if (EVP_Digest(destination.data(), destination.size(), digest.data(), &digestLength, EVP_sha256(), nullptr) != 1 || digestLength != 32) {
		throw SamException("Unable to calculate I2P destination hash");
	}

	auto b32 = Encoder::toBase32(digest.data(), digestLength);
	return toLowerAscii(std::move(b32)) + ".b32.i2p";
}

SamSocket::SamSocket() noexcept : handle(INVALID_HANDLE) {
}

SamSocket::SamSocket(Handle aHandle) noexcept : handle(aHandle) {
}

SamSocket::~SamSocket() noexcept {
	close();
}

SamSocket::SamSocket(SamSocket&& rhs) noexcept : handle(rhs.handle) {
	rhs.handle = INVALID_HANDLE;
}

SamSocket& SamSocket::operator=(SamSocket&& rhs) noexcept {
	if (this != &rhs) {
		close();
		handle = rhs.handle;
		rhs.handle = INVALID_HANDLE;
	}

	return *this;
}

void SamSocket::initializePlatform() {
#ifdef _WIN32
	static std::once_flag initialized;
	static int result = 0;
	std::call_once(initialized, [] {
		WSADATA data;
		result = WSAStartup(MAKEWORD(2, 2), &data);
	});
	if (result != 0) {
		throw SamException("Unable to initialize local SAM socket support");
	}
#endif
}

void SamSocket::setBlocking(Handle aHandle, bool aBlocking) {
#ifdef _WIN32
	u_long mode = aBlocking ? 0 : 1;
	if (ioctlsocket(aHandle, FIONBIO, &mode) != 0) {
		throw SamException("Unable to configure local SAM socket");
	}
#else
	auto flags = fcntl(aHandle, F_GETFL, 0);
	if (flags == -1 || fcntl(aHandle, F_SETFL, aBlocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK)) == -1) {
		throw SamException("Unable to configure local SAM socket");
	}
#endif
}

void SamSocket::waitFor(Handle aHandle, bool aRead, bool aWrite, std::chrono::milliseconds aTimeout) {
	if (aTimeout.count() < 0) {
		throw SamException("Invalid SAM timeout");
	}

	fd_set readSet;
	fd_set writeSet;
	FD_ZERO(&readSet);
	FD_ZERO(&writeSet);
	if (aRead) {
		FD_SET(aHandle, &readSet);
	}
	if (aWrite) {
		FD_SET(aHandle, &writeSet);
	}

	timeval timeout;
	timeout.tv_sec = static_cast<long>(aTimeout.count() / 1000);
	timeout.tv_usec = static_cast<long>((aTimeout.count() % 1000) * 1000);

	auto result = select(
#ifdef _WIN32
		0,
#else
		aHandle + 1,
#endif
		aRead ? &readSet : nullptr,
		aWrite ? &writeSet : nullptr,
		nullptr,
		&timeout
	);
	if (result == 0) {
		throw SamException("Timed out waiting for local SAM bridge");
	}
	if (result < 0) {
		throw SamException("Local SAM socket wait failed");
	}
}

int SamSocket::getLastError() noexcept {
#ifdef _WIN32
	return WSAGetLastError();
#else
	return errno;
#endif
}

void SamSocket::closeHandle(Handle aHandle) noexcept {
#ifdef _WIN32
	closesocket(aHandle);
#else
	::close(aHandle);
#endif
}

SamSocket SamSocket::connect(const SamEndpoint& aEndpoint, std::chrono::milliseconds aTimeout) {
	aEndpoint.validate();
	initializePlatform();

	const auto family = aEndpoint.host == "::1" ? AF_INET6 : AF_INET;
	auto socket = ::socket(family, SOCK_STREAM, IPPROTO_TCP);
	if (socket == INVALID_HANDLE) {
		throw SamException("Unable to create local SAM socket");
	}

	try {
		setBlocking(socket, false);
		int result = -1;
		if (family == AF_INET) {
			sockaddr_in address { };
			address.sin_family = AF_INET;
			address.sin_port = htons(aEndpoint.port);
			if (inet_pton(AF_INET, aEndpoint.host.c_str(), &address.sin_addr) != 1) {
				throw SamException("Invalid SAM loopback address");
			}
			result = ::connect(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address));
		} else {
			sockaddr_in6 address { };
			address.sin6_family = AF_INET6;
			address.sin6_port = htons(aEndpoint.port);
			if (inet_pton(AF_INET6, aEndpoint.host.c_str(), &address.sin6_addr) != 1) {
				throw SamException("Invalid SAM loopback address");
			}
			result = ::connect(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address));
		}

		if (result == -1) {
			auto error = getLastError();
			if (!isConnectInProgress(error)) {
				throw SamException("Unable to connect to local SAM bridge at " + aEndpoint.toString());
			}

			waitFor(socket, false, true, aTimeout);
			int socketError = 0;
#ifdef _WIN32
			int socketErrorLength = sizeof(socketError);
			if (getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&socketError), &socketErrorLength) != 0) {
#else
			socklen_t socketErrorLength = sizeof(socketError);
			if (getsockopt(socket, SOL_SOCKET, SO_ERROR, &socketError, &socketErrorLength) != 0) {
#endif
				throw SamException("Unable to inspect local SAM socket");
			}
			if (socketError != 0) {
				throw SamException("Unable to connect to local SAM bridge at " + aEndpoint.toString());
			}
		}

		setBlocking(socket, true);
		return SamSocket(socket);
	} catch (...) {
		closeHandle(socket);
		throw;
	}
}

bool SamSocket::isOpen() const noexcept {
	return handle != INVALID_HANDLE;
}

void SamSocket::close() noexcept {
	if (isOpen()) {
		closeHandle(handle);
		handle = INVALID_HANDLE;
	}
}

void SamSocket::write(std::string_view aData, std::chrono::milliseconds aTimeout) {
	if (!isOpen()) {
		throw SamException("Local SAM socket is closed");
	}

	size_t offset = 0;
	while (offset < aData.size()) {
		waitFor(handle, false, true, aTimeout);
#ifdef MSG_NOSIGNAL
		constexpr int SEND_FLAGS = MSG_NOSIGNAL;
#else
		constexpr int SEND_FLAGS = 0;
#endif
		auto length = std::min(aData.size() - offset, static_cast<size_t>(std::numeric_limits<int>::max()));
		auto sent = ::send(handle, aData.data() + offset, static_cast<int>(length), SEND_FLAGS);
		if (sent <= 0) {
			throw SamException("Unable to write to local SAM bridge");
		}

		offset += static_cast<size_t>(sent);
	}
}

void SamSocket::writeLine(std::string_view aLine, std::chrono::milliseconds aTimeout) {
	if (containsLineBreak(aLine)) {
		throw SamException("SAM command contains an unexpected line break");
	}

	write(aLine, aTimeout);
	write("\n", aTimeout);
}

std::string SamSocket::readLine(std::chrono::milliseconds aTimeout, size_t aMaximumLength) {
	if (!isOpen()) {
		throw SamException("Local SAM socket is closed");
	}

	std::string line;
	line.reserve(256);
	while (line.size() <= aMaximumLength) {
		char ch = 0;
		if (read(&ch, 1, aTimeout) == 0) {
			throw SamException("Local SAM bridge closed the connection");
		}

		if (ch == '\n') {
			return trimLineEndings(std::move(line));
		}

		line += ch;
	}

	throw SamException("SAM response exceeded the maximum line length");
}

size_t SamSocket::read(void* aBuffer, size_t aLength, std::chrono::milliseconds aTimeout) {
	if (!isOpen()) {
		throw SamException("Local SAM socket is closed");
	}
	if (aLength == 0) {
		return 0;
	}

	waitFor(handle, true, false, aTimeout);
	auto length = std::min(aLength, static_cast<size_t>(std::numeric_limits<int>::max()));
	auto received = ::recv(handle, static_cast<char*>(aBuffer), static_cast<int>(length), 0);
	if (received < 0) {
		throw SamException("Unable to read from local SAM bridge");
	}

	return static_cast<size_t>(received);
}

std::optional<std::string> SamIdentityStore::load(const std::filesystem::path& aPath) {
	#ifndef _WIN32
	int flags = O_RDONLY;
	#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
	#endif
	#ifdef O_CLOEXEC
	flags |= O_CLOEXEC;
	#endif

	int descriptor = ::open(aPath.c_str(), flags);
	if (descriptor == -1) {
		if (errno == ENOENT) {
			return std::nullopt;
		}

		throw SamException("Unable to open I2P identity file");
	}

	try {
		struct stat status { };
		if (fstat(descriptor, &status) != 0) {
			throw SamException("Unable to inspect I2P identity file permissions");
		}
		if (!S_ISREG(status.st_mode) || status.st_uid != geteuid() || (status.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
			throw SamException("I2P identity file must be a private regular file");
		}
		if (status.st_size <= 0 || static_cast<uintmax_t>(status.st_size) > MAXIMUM_IDENTITY_FILE_LENGTH) {
			throw SamException("I2P identity file has an invalid size");
		}

		std::string privateDestination(static_cast<size_t>(status.st_size), '\0');
		size_t offset = 0;
		while (offset < privateDestination.size()) {
			auto received = ::read(descriptor, privateDestination.data() + offset, privateDestination.size() - offset);
			if (received < 0) {
				if (errno == EINTR) {
					continue;
				}
				throw SamException("Unable to read I2P identity file");
			}
			if (received == 0) {
				throw SamException("I2P identity file changed while reading");
			}

			offset += static_cast<size_t>(received);
		}

		if (::close(descriptor) != 0) {
			descriptor = -1;
			throw SamException("Unable to close I2P identity file");
		}
		descriptor = -1;

		privateDestination = trimLineEndings(std::move(privateDestination));
		if (privateDestination.size() < MINIMUM_PUBLIC_DESTINATION_LENGTH || !std::all_of(privateDestination.begin(), privateDestination.end(), isBase64Character)) {
			throw SamException("I2P identity file is invalid");
		}

		return privateDestination;
	} catch (...) {
		if (descriptor != -1) {
			::close(descriptor);
		}
		throw;
	}
	#else
	std::error_code error;
	if (!std::filesystem::exists(aPath, error)) {
		if (error) {
			throw SamException("Unable to inspect I2P identity file");
		}
		return std::nullopt;
	}
	auto fileSize = std::filesystem::file_size(aPath, error);
	if (error || fileSize == 0 || fileSize > MAXIMUM_IDENTITY_FILE_LENGTH) {
		throw SamException("I2P identity file has an invalid size");
	}

	std::ifstream input(aPath, std::ios::binary);
	if (!input) {
		throw SamException("Unable to open I2P identity file");
	}

	std::string privateDestination((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
	privateDestination = trimLineEndings(std::move(privateDestination));
	if (privateDestination.size() < MINIMUM_PUBLIC_DESTINATION_LENGTH || !std::all_of(privateDestination.begin(), privateDestination.end(), isBase64Character)) {
		throw SamException("I2P identity file is invalid");
	}

	return privateDestination;
	#endif
}

void SamIdentityStore::save(const std::filesystem::path& aPath, const std::string& aPrivateDestination) {
	if (aPrivateDestination.size() < MINIMUM_PUBLIC_DESTINATION_LENGTH || containsLineBreak(aPrivateDestination) || !std::all_of(aPrivateDestination.begin(), aPrivateDestination.end(), isBase64Character)) {
		throw SamException("Refusing to save an invalid I2P identity");
	}

	std::error_code error;
	if (!aPath.parent_path().empty()) {
		std::filesystem::create_directories(aPath.parent_path(), error);
		if (error) {
			throw SamException("Unable to create I2P identity directory");
		}
	}

	auto temporaryPath = aPath;
	temporaryPath += ".tmp-" + randomHex(8);
	try {
		#ifndef _WIN32
		int flags = O_WRONLY | O_CREAT | O_EXCL;
		#ifdef O_NOFOLLOW
		flags |= O_NOFOLLOW;
		#endif
		#ifdef O_CLOEXEC
		flags |= O_CLOEXEC;
		#endif
		int descriptor = ::open(temporaryPath.c_str(), flags, S_IRUSR | S_IWUSR);
		if (descriptor == -1) {
			throw SamException("Unable to create I2P identity file");
		}

		try {
			const auto contents = aPrivateDestination + '\n';
			size_t offset = 0;
			while (offset < contents.size()) {
				auto written = ::write(descriptor, contents.data() + offset, contents.size() - offset);
				if (written < 0) {
					if (errno == EINTR) {
						continue;
					}
					throw SamException("Unable to write I2P identity file");
				}
				if (written == 0) {
					throw SamException("Unable to write I2P identity file");
				}

				offset += static_cast<size_t>(written);
			}

			if (fsync(descriptor) != 0) {
				throw SamException("Unable to finalize I2P identity file");
			}
			if (::close(descriptor) != 0) {
				descriptor = -1;
				throw SamException("Unable to close I2P identity file");
			}
			descriptor = -1;
		} catch (...) {
			if (descriptor != -1) {
				::close(descriptor);
			}
			throw;
		}
		#else
		{
			std::ofstream output(temporaryPath, std::ios::binary | std::ios::trunc);
			if (!output) {
				throw SamException("Unable to create I2P identity file");
			}
			output << aPrivateDestination << '\n';
			output.flush();
			if (!output) {
				throw SamException("Unable to write I2P identity file");
			}
		}
		#endif

		std::filesystem::rename(temporaryPath, aPath, error);
#ifdef _WIN32
		if (error) {
			std::filesystem::remove(aPath, error);
			error.clear();
			std::filesystem::rename(temporaryPath, aPath, error);
		}
#endif
		if (error) {
			throw SamException("Unable to finalize I2P identity file");
		}
	} catch (...) {
		std::filesystem::remove(temporaryPath, error);
		throw;
	}
}

SamSession::SamSession(SamEndpoint aEndpoint, std::filesystem::path aIdentityPath, SamSessionOptions aOptions) :
	endpoint(std::move(aEndpoint)),
	identityPath(std::move(aIdentityPath)),
	options(std::move(aOptions))
{
	endpoint.validate();
	if (options.inboundQuantity == 0 || options.outboundQuantity == 0) {
		throw SamException("I2P tunnel quantities must be nonzero");
	}
	if (options.sessionId.empty()) {
		options.sessionId = generateSessionId();
	}
	if (!isValidSessionId(options.sessionId)) {
		throw SamException("I2P session ID contains unsupported characters");
	}
}

SamSession::~SamSession() noexcept {
	stop();
}

std::string SamSession::generateSessionId() {
	return "airdcpp-i2p-" + randomHex(12);
}

SamReply SamSession::transact(SamSocket& aSocket, std::string_view aCommand, std::chrono::milliseconds aTimeout) {
	aSocket.writeLine(aCommand, aTimeout);
	return parseSamReply(aSocket.readLine(aTimeout));
}

void SamSession::hello(SamSocket& aSocket, std::chrono::milliseconds aTimeout, std::string& aVersion) {
	auto reply = transact(aSocket, "HELLO VERSION MIN=3.1 MAX=3.3", aTimeout);
	requireOk(reply, "HELLO", "REPLY");
	auto version = reply.get("VERSION");
	if (!version || !versionAtLeast(*version, 3, 1)) {
		throw SamException("SAM bridge does not support SAM 3.1");
	}

	aVersion = *version;
}

void SamSession::requireOk(const SamReply& aReply, const std::string& aCommand, const std::string& aSubcommand) {
	if (aReply.command != aCommand || aReply.subcommand != aSubcommand) {
		throw SamException("Unexpected SAM response while processing " + aCommand + " " + aSubcommand);
	}

	auto result = aReply.get("RESULT");
	if (!result || *result != "OK") {
		throw SamException(safeMessage(aReply));
	}
}

SamSocket SamSession::openSocket(std::chrono::milliseconds aTimeout) const {
	return SamSocket::connect(endpoint, aTimeout);
}

void SamSession::loadOrCreateIdentity(SamSocket& aSocket) {
	auto existing = SamIdentityStore::load(identityPath);
	if (existing) {
		privateDestination = std::move(*existing);
		return;
	}

	auto reply = transact(aSocket, "DEST GENERATE SIGNATURE_TYPE=7", options.sessionTimeout);
	if (reply.command != "DEST" || reply.subcommand != "REPLY") {
		throw SamException("Unexpected SAM response while generating I2P identity");
	}

	auto publicDestination = reply.get("PUB");
	auto generatedPrivateDestination = reply.get("PRIV");
	if (!publicDestination || !generatedPrivateDestination || !isI2PDestination(*publicDestination) || !isI2PDestination(*generatedPrivateDestination)) {
		throw SamException("SAM bridge returned an invalid I2P identity");
	}

	SamIdentityStore::save(identityPath, *generatedPrivateDestination);
	privateDestination = std::move(*generatedPrivateDestination);
}

void SamSession::createSession(SamSocket& aSocket) {
	const auto command = "SESSION CREATE STYLE=STREAM ID=" + options.sessionId +
		" DESTINATION=" + privateDestination +
		" SIGNATURE_TYPE=7 i2cp.leaseSetEncType=4 inbound.quantity=" + std::to_string(options.inboundQuantity) +
		" outbound.quantity=" + std::to_string(options.outboundQuantity);
	requireOk(transact(aSocket, command, options.sessionTimeout), "SESSION", "STATUS");
}

void SamSession::refreshPublicDestination(SamSocket& aSocket) {
	auto reply = transact(aSocket, "NAMING LOOKUP NAME=ME", options.handshakeTimeout);
	requireOk(reply, "NAMING", "REPLY");
	auto publicDestination = reply.get("VALUE");
	if (!publicDestination || !isI2PDestination(*publicDestination)) {
		throw SamException("SAM bridge did not return the active I2P destination");
	}

	identity.publicDestination = std::move(*publicDestination);
	identity.b32Address = destinationToB32(identity.publicDestination);
}

void SamSession::start() {
	std::lock_guard lock(mutex);
	if (controlSocket && controlSocket->isOpen()) {
		return;
	}

	controlSocket.reset();
	identity = { };
	privateDestination.clear();
	negotiatedVersion.clear();

	try {
		auto socket = std::make_unique<SamSocket>(openSocket(options.handshakeTimeout));
		hello(*socket, options.handshakeTimeout, negotiatedVersion);
		loadOrCreateIdentity(*socket);
		createSession(*socket);
		refreshPublicDestination(*socket);
		controlSocket = std::move(socket);
	} catch (...) {
		controlSocket.reset();
		identity = { };
		privateDestination.clear();
		negotiatedVersion.clear();
		throw;
	}
}

void SamSession::stop() noexcept {
	std::lock_guard lock(mutex);
	controlSocket.reset();
	identity = { };
	privateDestination.clear();
	negotiatedVersion.clear();
}

bool SamSession::isStarted() const noexcept {
	std::lock_guard lock(mutex);
	return controlSocket && controlSocket->isOpen();
}

SamIdentity SamSession::getIdentity() const {
	std::lock_guard lock(mutex);
	if (!controlSocket || identity.publicDestination.empty()) {
		throw SamException("I2P session is not started");
	}

	return identity;
}

std::string SamSession::lookup(const std::string& aName) {
	if (!isI2PDestination(aName)) {
		throw SamException("Only valid I2P destinations may be looked up");
	}

	std::lock_guard lock(mutex);
	if (!controlSocket || !controlSocket->isOpen()) {
		throw SamException("I2P session is not started");
	}

	auto reply = transact(*controlSocket, "NAMING LOOKUP NAME=" + aName, options.streamTimeout);
	requireOk(reply, "NAMING", "REPLY");
	auto destination = reply.get("VALUE");
	if (!destination || !isI2PDestination(*destination)) {
		throw SamException("SAM bridge returned an invalid I2P destination");
	}

	return *destination;
}

std::unique_ptr<SamSocket> SamSession::connect(const std::string& aDestination) {
	if (!isI2PDestination(aDestination)) {
		throw SamException("Refusing to create a non-I2P stream");
	}

	std::lock_guard lock(mutex);
	if (!controlSocket || !controlSocket->isOpen()) {
		throw SamException("I2P session is not started");
	}

	auto stream = std::make_unique<SamSocket>(openSocket(options.handshakeTimeout));
	std::string streamVersion;
	hello(*stream, options.handshakeTimeout, streamVersion);
	requireOk(transact(*stream, "STREAM CONNECT ID=" + options.sessionId + " DESTINATION=" + aDestination, options.streamTimeout), "STREAM", "STATUS");
	return stream;
}

SamIncomingStream SamSession::accept() {
	std::lock_guard lock(mutex);
	if (!controlSocket || !controlSocket->isOpen()) {
		throw SamException("I2P session is not started");
	}

	auto stream = std::make_unique<SamSocket>(openSocket(options.handshakeTimeout));
	std::string streamVersion;
	hello(*stream, options.handshakeTimeout, streamVersion);
	requireOk(transact(*stream, "STREAM ACCEPT ID=" + options.sessionId, options.streamTimeout), "STREAM", "STATUS");

	auto peerDestination = stream->readLine(options.streamTimeout);
	if (peerDestination.starts_with("STREAM STATUS")) {
		auto reply = parseSamReply(peerDestination);
		throw SamException(safeMessage(reply));
	}
	if (!isI2PDestination(peerDestination)) {
		throw SamException("SAM bridge returned an invalid incoming I2P destination");
	}

	return { std::move(stream), std::move(peerDestination) };
}

bool SamSession::ping(const std::string& aPayload) {
	if (aPayload.size() > 1024 || containsLineBreak(aPayload)) {
		throw SamException("SAM ping payload contains an unexpected line break");
	}

	std::lock_guard lock(mutex);
	if (!controlSocket || !controlSocket->isOpen()) {
		throw SamException("I2P session is not started");
	}
	if (!versionAtLeast(negotiatedVersion, 3, 2)) {
		return false;
	}

	controlSocket->writeLine("PING " + aPayload, options.handshakeTimeout);
	auto response = controlSocket->readLine(options.handshakeTimeout);
	if (!response.starts_with("PONG")) {
		throw SamException("Unexpected SAM keepalive response");
	}

	return true;
}

} // namespace dcpp::i2p
