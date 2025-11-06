#ifndef WAR3NAT_H
#define WAR3NAT_H

#include <QMap>
#include <QSet>
#include <QTimer>
#include <QVector>
#include <QObject>
#include <QDateTime>
#include <QUdpSocket>
#include <QHostAddress>
#include <QElapsedTimer>
#include <QCryptographicHash>
#include <QSharedPointer>
#include <QThreadPool>

// STUN消息类型 (RFC 5389)
enum STUNMessageType {
    STUN_BINDING_REQUEST = 0x0001,
    STUN_BINDING_RESPONSE = 0x0101
};

// TURN消息类型 (RFC 5766)
enum TURNMessageType {
    TURN_ALLOCATE_REQUEST = 0x0003,
    TURN_ALLOCATE_RESPONSE = 0x0103,
    TURN_REFRESH_REQUEST = 0x0004,
    TURN_REFRESH_RESPONSE = 0x0104,
    TURN_SEND_INDICATION = 0x0016,
    TURN_DATA_INDICATION = 0x0017,
    TURN_CREATE_PERMISSION = 0x0008,
    TURN_CREATE_PERMISSION_RESPONSE = 0x0108,
    TURN_CHANNEL_BIND = 0x0009,
    TURN_CHANNEL_BIND_RESPONSE = 0x0109
};

// 属性类型
enum AttributeType {
    STUN_ATTR_MAPPED_ADDRESS = 0x0001,
    STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020,
    TURN_ATTR_CHANNEL_NUMBER = 0x000C,
    TURN_ATTR_LIFETIME = 0x000D,
    TURN_ATTR_XOR_PEER_ADDRESS = 0x0012,
    TURN_ATTR_DATA = 0x0013,
    TURN_ATTR_XOR_RELAYED_ADDRESS = 0x0016,
    TURN_ATTR_EVEN_PORT = 0x0018,
    TURN_ATTR_REQUESTED_TRANSPORT = 0x0019,
    TURN_ATTR_DONT_FRAGMENT = 0x001A,
    TURN_ATTR_RESERVATION_TOKEN = 0x0022,
    STUN_ATTR_USERNAME = 0x0006,
    STUN_ATTR_MESSAGE_INTEGRITY = 0x0008,
    STUN_ATTR_REALM = 0x0014,
    STUN_ATTR_NONCE = 0x0015,
    STUN_ATTR_ERROR_CODE = 0x0009
};

// NAT类型
enum NATType {
    NAT_UNKNOWN,
    NAT_OPEN_INTERNET,
    NAT_FULL_CONE,
    NAT_RESTRICTED_CONE,
    NAT_PORT_RESTRICTED_CONE,
    NAT_SYMMETRIC,
    NAT_SYMMETRIC_UDP_FIREWALL,
    NAT_BLOCKED
};

// 中继服务器信息
struct RelayServer {
    QString id;
    QString name;
    QHostAddress address;
    quint16 port;
    QString region;
    int priority;
    bool enabled;
    double latency;
    double jitter;
    double packetLoss;
    int score;
    RelayServer() : port(3478), priority(50), enabled(true),
        latency(0), jitter(0), packetLoss(0), score(0) {}
};

// 中继分配信息
struct Allocation {
    QString allocationId;
    QHostAddress clientAddr;
    quint16 clientPort;
    QHostAddress relayAddr;
    quint16 relayPort;
    QDateTime expiryTime;
    quint32 lifetime;
    QSet<QPair<QString, quint16>> permissions;
    QMap<quint16, QPair<QString, quint16>> channelBindings;
    QString username; // 新增: 用于认证
};

// 测试结果
struct RelayTestResult {
    QString serverId;
    double latency;
    double jitter;
    double packetLoss;
    bool reachable;
    int score;
    QDateTime testTime;
};

struct RequestInfo {
    QHostAddress clientAddr;
    quint16 clientPort;
    qint64 timestamp;
};

class War3Nat : public QObject
{
    Q_OBJECT
public:
    explicit War3Nat(QObject *parent = nullptr);
    ~War3Nat();

    // 服务器管理
    void stopServer();
    bool startServer(quint16 port = 3478);
    bool isRunning() const { return m_isRunning; }
    quint16 serverPort() const { return m_serverPort; }
    void setMaxAllocations(int max) { m_maxAllocations = max; }
    int allocationCount() const { return m_allocations.size(); }
    void setForcePortReuse(bool reuse) { m_forcePortReuse = reuse; }

    // 中继服务器管理
    QVector<RelayServer> getRelayServers() const;
    void addRelayServer(const RelayServer &server);
    void removeRelayServer(const QString &serverId);
    void setRelayServers(const QVector<RelayServer> &servers);

    // 中继选择
    void startRelaySelection();
    void stopRelaySelection();
    RelayServer getOptimalRelay() const;
    QVector<RelayTestResult> getTestResults() const;

    // NAT类型检测 (客户端功能)
    NATType detectNATType(const QVector<RelayServer> &stunServers);

signals:
    void relaySelectionStarted();
    void relayTestProgress(const QString &serverId, int progress);
    void relayTestCompleted(const RelayTestResult &result);
    void optimalRelaySelected(const RelayServer &server);
    void relaySelectionFinished();
    void allocationCreated(const QString &allocationId, const QHostAddress &relayAddr, quint16 relayPort);
    void allocationRefreshed(const QString &allocationId, quint32 newLifetime);
    void allocationExpired(const QString &allocationId);

private slots:
    void onNextTest();
    void onReadyRead();
    void onTestTimeout();
    void onCleanupTimeout();
    void onAllocationExpiryCheck();

private:
    // STUN处理
    void handleSTUNRequest(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort);
    QByteArray buildSTUNResponse(const QByteArray &request, const QHostAddress &clientAddr, quint16 clientPort);

    // TURN处理
    void handleTURNRequest(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort);
    void handleAllocateRequest(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId);
    void handleRefreshRequest(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId);
    void handleCreatePermission(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId);
    void handleSendIndication(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort);
    void handleChannelBind(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId);

    // 认证相关 (新增)
    bool authenticateRequest(const QByteArray &data, const QByteArray &transactionId, QString &username, const QHostAddress &clientAddr, quint16 clientPort);

    // TURN响应构建
    QByteArray buildAllocateResponse(const QByteArray &transactionId, const QHostAddress &relayAddr, quint16 relayPort, quint32 lifetime = 600);
    QByteArray buildRefreshResponse(const QByteArray &transactionId, quint32 lifetime);
    QByteArray buildCreatePermissionResponse(const QByteArray &transactionId);
    QByteArray buildChannelBindResponse(const QByteArray &transactionId);
    QByteArray buildErrorResponse(const QByteArray &transactionId, quint16 errorCode, const QString &reason);

    // 中继选择功能
    RelayServer selectOptimalRelay();
    void performRelayTest(const RelayServer &server);
    void processTestResponse(const QByteArray &data);
    void completeServerTest(const QString &serverId);
    int calculateScore(const RelayTestResult &result);
    void sendTestPacket(const RelayServer &server, int seq);

    // 中继数据处理
    void relayDataToPeer(const QByteArray &data, const QHostAddress &fromAddr, quint16 fromPort,
                         const QHostAddress &toAddr, quint16 toPort);
    bool validatePermission(const Allocation &allocation, const QHostAddress &peerAddr, quint16 peerPort);

    // 工具方法
    QByteArray generateNonce();
    QByteArray generateTransactionId();
    QHostAddress allocateRelayAddress();
    quint16 allocateRelayPort(bool evenPort);
    QByteArray createTestPacket(int sequence, const QByteArray &serverId);
    bool parseTestResponse(const QByteArray &data, int &sequence, QByteArray &serverId);
    void logRequest(const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId);
    void logResponse(const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId);
    void logTURNAction(const QString &action, const QHostAddress &clientAddr, quint16 clientPort, const QString &details = "");

    // NAT检测内部方法 (更新)
    bool sendSTUNBindingRequest(QUdpSocket *socket, const QHostAddress &serverAddr, quint16 serverPort, QByteArray &response, QHostAddress &mappedAddr, quint16 &mappedPort, bool changeIP = false, bool changePort = false);

    // HMAC-SHA1 计算 (新增)
    QByteArray hmacSha1(const QByteArray &key, const QByteArray &message);

private:
    QUdpSocket *m_udpSocket;
    quint16 m_serverPort;
    bool m_isRunning;
    bool m_forcePortReuse;

    // STUN相关
    int m_totalRequests;
    int m_totalResponses;
    QMap<QByteArray, RequestInfo> m_recentRequests;
    QTimer *m_cleanupTimer;

    // TURN相关
    QMap<QString, QSharedPointer<Allocation>> m_allocations;
    QMap<QPair<QString, quint16>, QString> m_relayMapping;
    QSet<quint16> m_usedRelayPorts;
    QTimer *m_allocationTimer;
    int m_maxAllocations = 1000;

    // 认证配置
    QString m_realm = "war3nat";
    QMap<QString, QString> m_users; // username -> password (简单存储，生产用数据库)

    // 中继选择相关
    QVector<RelayServer> m_relayServers;
    QMap<QString, RelayTestResult> m_testResults;
    QTimer *m_testTimer;
    QTimer *m_selectionTimer;

    // 测试状态
    int m_currentTestIndex;
    int m_currentPacketSeq;
    QMap<QByteArray, QElapsedTimer> m_packetTimers;
    QMap<QString, QVector<qint64>> m_latencySamples;
    bool m_testInProgress;

    // 配置
    QHostAddress m_relayAddress;
    quint16 m_minRelayPort;
    quint16 m_maxRelayPort;
    quint32 m_defaultLifetime;
    int m_testCount;
    int m_testTimeout;
    bool m_autoSelection;
    int m_testInterval = 200; // 测试包间隔ms，防止洪泛

    // 权重配置
    double m_latencyWeight;
    double m_jitterWeight;
    double m_packetLossWeight;
    double m_priorityWeight;

    // 线程池
    QThreadPool *m_threadPool;
};
#endif // WAR3NAT_H
