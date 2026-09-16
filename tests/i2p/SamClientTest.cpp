#include <airdcpp/i2p/SamClient.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <exception>
#include <filesystem>
#include <functional>
#include <iostream>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

using namespace dcpp::i2p;

constexpr auto IO_TIMEOUT = std::chrono::seconds(5);

const std::string& lookupDestination() {
	static const std::string destination = [] {
		std::string value(52, 'a');
		value += ".b32.i2p";
		return value;
	}();
	return destination;
}

void require(bool aCondition, const std::string& aMessage) {
	if (!aCondition) {
		throw std::runtime_error(aMessage);
	}
}

template<typename Function>
void requireThrows(Function&& aFunction, const std::string& aMessage) {
	try {
		aFunction();
	} catch (const SamException&) {
		return;
	}

	throw std::runtime_error(aMessage);
}

void writeAll(int aSocket, std::string_view aData) {
	size_t offset = 0;
	while (offset < aData.size()) {
#ifdef MSG_NOSIGNAL
		constexpr int SEND_FLAGS = MSG_NOSIGNAL;
#else
		constexpr int SEND_FLAGS = 0;
#endif
		auto sent = ::send(aSocket, aData.data() + offset, aData.size() - offset, SEND_FLAGS);
		if (sent < 0 && errno == EINTR) {
			continue;
		}
		if (sent <= 0) {
			throw std::runtime_error("Fake SAM bridge could not write a response");
		}

		offset += static_cast<size_t>(sent);
	}
}

void writeLine(int aSocket, const std::string& aLine) {
	writeAll(aSocket, aLine + '\n');
}

std::optional<std::string> readLine(int aSocket) {
	std::string line;
	line.reserve(128);
	while (line.size() <= 64 * 1024) {
		char ch = 0;
		auto received = ::recv(aSocket, &ch, 1, 0);
		if (received < 0 && errno == EINTR) {
			continue;
		}
		if (received == 0) {
			return std::nullopt;
		}
		if (received < 0) {
			throw std::runtime_error("Fake SAM bridge timed out waiting for a command");
		}
		if (ch == '\n') {
			if (!line.empty() && line.back() == '\r') {
				line.pop_back();
			}
			return line;
		}

		line += ch;
	}

	throw std::runtime_error("Fake SAM bridge received an oversized command");
}

std::string requireLine(int aSocket) {
	auto line = readLine(aSocket);
	if (!line) {
		throw std::runtime_error("Fake SAM bridge connection closed unexpectedly");
	}

	return *line;
}

std::string readExact(int aSocket, size_t aLength) {
	std::string result(aLength, '\0');
	size_t offset = 0;
	while (offset < result.size()) {
		auto received = ::recv(aSocket, result.data() + offset, result.size() - offset, 0);
		if (received < 0 && errno == EINTR) {
			continue;
		}
		if (received <= 0) {
			throw std::runtime_error("Fake SAM bridge connection closed while reading stream data");
		}

		offset += static_cast<size_t>(received);
	}

	return result;
}

std::string readExact(SamSocket& aSocket, size_t aLength, std::chrono::milliseconds aTimeout) {
	std::string result(aLength, '\0');
	size_t offset = 0;
	while (offset < result.size()) {
		offset += aSocket.read(result.data() + offset, result.size() - offset, aTimeout);
	}

	return result;
}

class FakeSamBridge {
public:
	FakeSamBridge() :
		publicDestination(516, 'A'),
		privateDestination(884, 'A')
	{
		auto socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (socket == -1) {
			throw std::runtime_error("Unable to create fake SAM bridge listener");
		}

		try {
			int enabled = 1;
			if (setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0) {
				throw std::runtime_error("Unable to configure fake SAM bridge listener");
			}

			sockaddr_in address { };
			address.sin_family = AF_INET;
			address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			address.sin_port = 0;
			if (bind(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 || listen(socket, 8) != 0) {
				throw std::runtime_error("Unable to start fake SAM bridge listener");
			}

			socklen_t length = sizeof(address);
			if (getsockname(socket, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
				throw std::runtime_error("Unable to read fake SAM bridge port");
			}

			portNumber = ntohs(address.sin_port);
			listener = socket;
			acceptThread = std::thread([this] { acceptConnections(); });
		} catch (...) {
			::close(socket);
			throw;
		}
	}

	~FakeSamBridge() {
		stop();
	}

	FakeSamBridge(const FakeSamBridge&) = delete;
	FakeSamBridge& operator=(const FakeSamBridge&) = delete;

	uint16_t port() const noexcept {
		return portNumber;
	}

	const std::string& getPublicDestination() const noexcept {
		return publicDestination;
	}

	const std::string& getPrivateDestination() const noexcept {
		return privateDestination;
	}

	void assertHealthy() const {
		std::lock_guard lock(failureMutex);
		if (failure) {
			std::rethrow_exception(failure);
		}
	}

	void stop() noexcept {
		if (stopping.exchange(true)) {
			return;
		}

		const auto listenerSocket = listener.exchange(-1);
		if (listenerSocket != -1) {
			::shutdown(listenerSocket, SHUT_RDWR);
			::close(listenerSocket);
		}

		{
			std::lock_guard lock(clientMutex);
			for (const auto client : clients) {
				::shutdown(client, SHUT_RDWR);
			}
		}

		if (acceptThread.joinable()) {
			acceptThread.join();
		}
		for (auto& handler : handlers) {
			if (handler.joinable()) {
				handler.join();
			}
		}
	}

private:
	std::atomic<bool> stopping { false };
	std::atomic<int> listener { -1 };
	uint16_t portNumber = 0;
	const std::string publicDestination;
	const std::string privateDestination;
	std::thread acceptThread;
	std::vector<std::thread> handlers;
	std::vector<int> clients;
	std::mutex clientMutex;
	mutable std::mutex failureMutex;
	std::exception_ptr failure;

	void recordFailure() noexcept {
		std::lock_guard lock(failureMutex);
		if (!failure) {
			failure = std::current_exception();
		}
	}

	void acceptConnections() noexcept {
		try {
			while (!stopping.load()) {
				auto client = ::accept(listener.load(), nullptr, nullptr);
				if (client < 0) {
					if (errno == EINTR) {
						continue;
					}
					if (stopping.load()) {
						return;
					}
					throw std::runtime_error("Fake SAM bridge could not accept a connection");
				}

				timeval timeout { IO_TIMEOUT.count(), 0 };
				if (setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
					::close(client);
					throw std::runtime_error("Fake SAM bridge could not set a client timeout");
				}

				{
					std::lock_guard lock(clientMutex);
					if (stopping.load()) {
						::close(client);
						return;
					}
					clients.push_back(client);
				}

				handlers.emplace_back([this, client] {
					handleConnection(client);
					::close(client);
				});
			}
		} catch (...) {
			recordFailure();
		}
	}

	void handleConnection(int aSocket) noexcept {
		try {
			require(requireLine(aSocket) == "HELLO VERSION MIN=3.1 MAX=3.3", "Unexpected SAM HELLO command");
			writeLine(aSocket, "HELLO REPLY RESULT=OK VERSION=3.2");

			auto command = requireLine(aSocket);
			if (command == "DEST GENERATE SIGNATURE_TYPE=7") {
				handleControl(aSocket);
			} else if (command.starts_with("STREAM CONNECT ID=")) {
				handleOutgoingStream(aSocket, command);
			} else if (command.starts_with("STREAM ACCEPT ID=")) {
				handleIncomingStream(aSocket, command);
			} else {
				throw std::runtime_error("Unexpected SAM command after HELLO");
			}
		} catch (...) {
			recordFailure();
		}
	}

	void handleControl(int aSocket) {
		writeLine(aSocket, "DEST REPLY PUB=" + publicDestination + " PRIV=" + privateDestination);

		auto sessionCreate = requireLine(aSocket);
		require(sessionCreate.starts_with("SESSION CREATE STYLE=STREAM ID=airdcpp-i2p-"), "SAM session did not use a STREAM session ID");
		require(sessionCreate.find(" SIGNATURE_TYPE=7") != std::string::npos, "SAM session did not request Ed25519");
		require(sessionCreate.find(" i2cp.leaseSetEncType=4") != std::string::npos, "SAM session did not request ECIES leasesets");
		require(sessionCreate.find(" inbound.quantity=3") != std::string::npos, "SAM session did not set inbound tunnel quantity");
		require(sessionCreate.find(" outbound.quantity=3") != std::string::npos, "SAM session did not set outbound tunnel quantity");
		writeLine(aSocket, "SESSION STATUS RESULT=OK");

		require(requireLine(aSocket) == "NAMING LOOKUP NAME=ME", "SAM session did not resolve its own destination");
		writeLine(aSocket, "NAMING REPLY RESULT=OK VALUE=" + publicDestination);

		while (auto command = readLine(aSocket)) {
			if (*command == "NAMING LOOKUP NAME=ME") {
				throw std::runtime_error("SAM session queried its active destination more than once");
			}
			if (*command == "NAMING LOOKUP NAME=" + lookupDestination()) {
				writeLine(aSocket, "NAMING REPLY RESULT=OK VALUE=" + publicDestination);
				continue;
			}
			if (command->starts_with("PING ")) {
				writeLine(aSocket, "PONG " + command->substr(5));
				continue;
			}

			throw std::runtime_error("Unexpected command on SAM control connection");
		}
	}

	void handleOutgoingStream(int aSocket, const std::string& aCommand) {
		require(aCommand.find(" DESTINATION=" + lookupDestination()) != std::string::npos, "Outgoing SAM stream used an unexpected destination");
		writeLine(aSocket, "STREAM STATUS RESULT=OK");
		require(readExact(aSocket, 4) == "ping", "Outgoing SAM stream data was altered");
		writeAll(aSocket, "pong");
	}

	void handleIncomingStream(int aSocket, const std::string& aCommand) {
		require(aCommand.starts_with("STREAM ACCEPT ID=airdcpp-i2p-"), "Incoming SAM stream used an unexpected session ID");
		writeLine(aSocket, "STREAM STATUS RESULT=OK");
		writeLine(aSocket, publicDestination);
		writeAll(aSocket, "incoming");
	}
};

class TemporaryDirectory {
public:
	explicit TemporaryDirectory(std::filesystem::path aPath) : path(std::move(aPath)) {
		std::filesystem::create_directories(path);
	}

	~TemporaryDirectory() {
		std::error_code error;
		std::filesystem::remove_all(path, error);
	}

	const std::filesystem::path path;
};

void runTests() {
	auto parsed = parseSamReply("HELLO REPLY RESULT=OK VERSION=3.2 MESSAGE=\"ready for streams\"");
	require(parsed.command == "HELLO" && parsed.subcommand == "REPLY", "SAM response parser lost command fields");
	require(parsed.get("VERSION") == std::optional<std::string>("3.2"), "SAM response parser lost VERSION");
	require(parsed.get("MESSAGE") == std::optional<std::string>("ready for streams"), "SAM response parser lost quoted MESSAGE");
	requireThrows([] { parseSamReply("HELLO REPLY RESULT=OK RESULT=ERROR"); }, "SAM response parser accepted a duplicate option");

	SamEndpoint invalidEndpoint;
	invalidEndpoint.host = "localhost";
	requireThrows([&] { invalidEndpoint.validate(); }, "SAM endpoint accepted a hostname");

	const auto uniqueName = "airdcpp-i2p-sam-test-" + std::to_string(getpid()) + "-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
	TemporaryDirectory temporaryDirectory(std::filesystem::temp_directory_path() / uniqueName);
	const auto identityPath = temporaryDirectory.path / "identity.dat";

	FakeSamBridge bridge;
	SamEndpoint endpoint;
	endpoint.port = bridge.port();
	SamSessionOptions options;
	options.handshakeTimeout = std::chrono::seconds(2);
	options.sessionTimeout = std::chrono::seconds(2);
	options.streamTimeout = std::chrono::seconds(2);
	SamSessionOptions invalidSessionOptions = options;
	invalidSessionOptions.sessionId = "invalid session";
	requireThrows([&] { SamSession invalidSession(endpoint, identityPath, invalidSessionOptions); }, "SAM session accepted an unsafe session ID");

	SamSession session(endpoint, identityPath, options);
	session.start();

	auto identity = session.getIdentity();
	require(identity.publicDestination == bridge.getPublicDestination(), "SAM session stored the wrong public destination");
	require(identity.b32Address == destinationToB32(bridge.getPublicDestination()), "SAM session computed the wrong b32 address");
	require(identity.b32Address.ends_with(".b32.i2p"), "SAM session did not expose a b32 address");
	require(SamIdentityStore::load(identityPath) == std::optional<std::string>(bridge.getPrivateDestination()), "SAM session did not persist the private destination");

	struct stat identityStatus { };
	require(::stat(identityPath.c_str(), &identityStatus) == 0, "Could not inspect persisted identity permissions");
	require((identityStatus.st_mode & (S_IRWXG | S_IRWXO)) == 0, "Persisted identity is readable outside its owner");

	require(session.lookup(lookupDestination()) == bridge.getPublicDestination(), "SAM lookup did not return the expected I2P destination");

	auto outgoing = session.connect(lookupDestination());
	outgoing->write("ping", options.streamTimeout);
	require(readExact(*outgoing, 4, options.streamTimeout) == "pong", "Outgoing I2P stream did not preserve data");

	auto incoming = session.accept();
	require(incoming.peerDestination == bridge.getPublicDestination(), "Incoming I2P stream did not report its peer destination");
	require(readExact(*incoming.socket, 8, options.streamTimeout) == "incoming", "Incoming I2P stream did not preserve data");

	require(session.ping("integration-check"), "SAM 3.2 keepalive was not available");
	session.stop();
	bridge.stop();
	bridge.assertHealthy();

	const auto symlinkPath = temporaryDirectory.path / "identity-link.dat";
	std::filesystem::create_symlink(identityPath, symlinkPath);
	requireThrows([&] { SamIdentityStore::load(symlinkPath); }, "I2P identity loader followed a symlink");
}

} // namespace

int main() {
	try {
		runTests();
		std::cout << "SAM client integration tests passed\n";
		return 0;
	} catch (const std::exception& error) {
		std::cerr << "SAM client integration test failed: " << error.what() << '\n';
		return 1;
	}
}
