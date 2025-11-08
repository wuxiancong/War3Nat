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

// ==================== 枚举定义 ====================

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

// NAT类型枚举 - 完整分类
enum NATType {
    NAT_UNKNOWN = 0,              // 未知
    NAT_OPEN_INTERNET = 1,        // 开放互联网（无NAT）
    NAT_FULL_CONE = 2,            // 完全锥形NAT
    NAT_RESTRICTED_CONE = 3,      // 限制锥形NAT
    NAT_PORT_RESTRICTED_CONE = 4, // 端口限制锥形NAT
    NAT_SYMMETRIC = 5,            // 对称型NAT
    NAT_SYMMETRIC_UDP_FIREWALL = 6, // 对称型UDP防火墙
    NAT_BLOCKED = 7,              // 被阻挡
    NAT_DOUBLE_NAT = 8,           // 双重NAT
    NAT_CARRIER_GRADE = 9,        // 运营商级NAT（CGNAT）
    NAT_IP_RESTRICTED = 10        // IP限制型NAT
};

// ==================== 数据结构定义 ====================

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

// 路径测试配置
struct PathTestConfig {
    QString testId;
    QHostAddress serverAddress;
    quint16 serverPort;
    QHostAddress clientA;
    QHostAddress clientB;
    int testCount;
    int timeoutMs;

    PathTestConfig() : serverPort(3478), testCount(5), timeoutMs(3000) {}
};

// 路径测试结果
struct PathTestResult {
    QString testId;
    QHostAddress serverAddress;
    double aToServerLatency;
    double bToServerLatency;
    double totalLatency;
    double jitter;
    double packetLoss;
    int score;
    bool reachable;
    QDateTime testTime;

    PathTestResult() : aToServerLatency(0), bToServerLatency(0), totalLatency(0),
        jitter(0), packetLoss(0), score(0), reachable(false) {}
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
    QString username;
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

// 请求信息
struct RequestInfo {
    QHostAddress clientAddr;
    quint16 clientPort;
    qint64 timestamp;
};

// STUN属性结构
struct STUNAttribute {
    quint16 type;
    quint16 length;
    QByteArray value;
};

// ==================== 前置声明 ====================

class PathTestTask;

// ==================== 主类定义 ====================

class War3Nat : public QObject
{
    Q_OBJECT

public:
    explicit War3Nat(QObject *parent = nullptr);
    ~War3Nat();

    // 服务器管理
    bool startServer(quint16 port = 3478);
    void stopServer();
    bool isRunning() const { return m_isRunning; }
    quint16 serverPort() const { return m_serverPort; }
    void setMaxAllocations(int max) { m_maxAllocations = max; }
    int allocationCount() const { return m_allocations.size(); }
    void setForcePortReuse(bool reuse) { m_forcePortReuse = reuse; }

    // 中继服务器管理
    void addRelayServer(const RelayServer &server);
    void removeRelayServer(const QString &serverId);
    void setRelayServers(const QVector<RelayServer> &servers);
    QVector<RelayServer> getRelayServers() const;

    // 中继选择
    void startRelaySelection();
    void stopRelaySelection();
    RelayServer getOptimalRelay() const;
    QVector<RelayTestResult> getTestResults() const;

    // 多路径测试
    void startMultiPathTest(const QVector<PathTestConfig> &testConfigs);
    void stopMultiPathTest();
    void performPathTest(const PathTestConfig &config);
    PathTestResult getOptimalPath() const;
    QVector<PathTestResult> getPathTestResults() const;

    // NAT类型检测
    NATType detectNATType(const QVector<RelayServer> &stunServers);

signals:
    // 中继选择信号
    void relaySelectionStarted();
    void relayTestProgress(const QString &serverId, int progress);
    void relayTestCompleted(const RelayTestResult &result);
    void optimalRelaySelected(const RelayServer &server);
    void relaySelectionFinished();

    // 多路径测试信号
    void multiPathTestStarted();
    void pathTestProgress(const QString &testId, int progress);
    void pathTestCompleted(const PathTestResult &result);
    void optimalPathSelected(const PathTestResult &result);
    void multiPathTestFinished();

    // 分配管理信号
    void allocationCreated(const QString &allocationId, const QHostAddress &relayAddr, quint16 relayPort);
    void allocationRefreshed(const QString &allocationId, quint32 newLifetime);
    void allocationExpired(const QString &allocationId);

private slots:
    void onReadyRead();
    void onNextTest();
    void onTestTimeout();
    void onCleanupTimeout();
    void onAllocationExpiryCheck();
    void onPathTestCompleted(const PathTestResult &result);

private:
    // ==================== STUN处理 ====================
    void handleSTUNRequest(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort);
    QByteArray buildSTUNResponse(const QByteArray &request, const QHostAddress &clientAddr, quint16 clientPort);

    // ==================== TURN处理 ====================
    void handleTURNRequest(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort);
    void handleAllocateRequest(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId);
    void handleRefreshRequest(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId);
    void handleCreatePermission(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId);
    void handleSendIndication(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort);
    void handleChannelBind(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId);
    void handleDataIndication(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort);
    void handlePathTestRequest(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort);

    // ==================== 认证相关 ====================
    bool authenticateRequest(const QByteArray &data, const QByteArray &transactionId, QString &username,
                             const QHostAddress &clientAddr, quint16 clientPort);
    QByteArray hmacSha1(const QByteArray &key, const QByteArray &message);

    // ==================== TURN响应构建 ====================
    QByteArray buildAllocateResponse(const QByteArray &transactionId, const QHostAddress &relayAddr,
                                     quint16 relayPort, quint32 lifetime = 600);
    QByteArray buildRefreshResponse(const QByteArray &transactionId, quint32 lifetime);
    QByteArray buildCreatePermissionResponse(const QByteArray &transactionId);
    QByteArray buildChannelBindResponse(const QByteArray &transactionId);
    QByteArray buildErrorResponse(const QByteArray &transactionId, quint16 errorCode, const QString &reason);

    // ==================== 中继选择功能 ====================
    void performRelayTest(const RelayServer &server);
    void sendTestPacket(const RelayServer &server, int seq);
    bool processTestResponse(const QByteArray &data);
    void completeServerTest(const QString &serverId);
    RelayServer selectOptimalRelay();
    int calculateScore(const RelayTestResult &result);

    // ==================== 多路径测试功能 ====================
    QVector<qint64> testOneWayLatency(const QHostAddress &from, const QHostAddress &to,
                                      quint16 port, int count);
    void finishMultiPathTest();
    PathTestResult selectOptimalPath() const;
    int calculatePathScore(const PathTestResult &result);
    double calculateAverageLatency(const QVector<qint64> &latencies);
    double calculateJitter(const QVector<qint64> &latenciesA, const QVector<qint64> &latenciesB);
    double calculatePacketLoss(const QVector<qint64> &latenciesA, const QVector<qint64> &latenciesB, int expectedCount);
    bool parsePathTestResponse(const QByteArray &data, int expectedSequence, const QByteArray &expectedTestId);

    // ==================== 中继数据处理 ====================
    void relayDataToPeer(const QByteArray &data, const QHostAddress &fromAddr, quint16 fromPort,
                         const QHostAddress &toAddr, quint16 toPort);
    bool validatePermission(const Allocation &allocation, const QHostAddress &peerAddr, quint16 peerPort);

    // ==================== 工具方法 ====================
    // 公共辅助方法
    QSharedPointer<Allocation> findAllocation(const QHostAddress &clientAddr, quint16 clientPort);
    bool validateAllocation(const QHostAddress &clientAddr, quint16 clientPort,
                            const QByteArray &transactionId, QByteArray &errorResponse);
    QVector<STUNAttribute> parseAttributes(const QByteArray &data, int startPos = 20);
    QHostAddress parseXorAddress(const QByteArray &data, int pos, quint16 &port);

    // 数据包处理
    QByteArray createTestPacket(int sequence, const QByteArray &serverId);
    QByteArray createPathTestPacket(int sequence, const QByteArray &testId);
    bool parseTestResponse(const QByteArray &data, int &sequence, QByteArray &serverId);
    bool processTestMessage(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort);
    void forwardToP2PServer(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort);
    void processRegisterRelayMessage(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort);
    bool validateRelayAddress(const QString &relayIp, quint16 relayPort, const QHostAddress &clientAddr, quint16 clientPort);
    void sendRelayRegistrationAck(const QHostAddress &clientAddr, quint16 clientPort, const QString &relayIp, const QString &relayPort);

    // 资源分配
    QHostAddress allocateRelayAddress();
    quint16 allocateRelayPort(bool evenPort);

    // 加密和ID生成
    QByteArray generateTransactionId();
    QByteArray generateNonce();

    // NAT检测
    bool sendSTUNBindingRequest(QUdpSocket *socket, const QHostAddress &serverAddr,
                                quint16 serverPort, QHostAddress &mappedAddr,
                                quint16 &mappedPort, bool changeIP, bool changePort);

    // ==================== 日志方法 ====================
    void logRequest(const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId);
    void logResponse(const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId);
    void logTURNAction(const QString &action, const QHostAddress &clientAddr, quint16 clientPort,
                       const QString &details = "");

private:
    // ==================== 成员变量 ====================

    // 网络相关
    QUdpSocket *m_udpSocket;
    quint16 m_serverPort;
    bool m_isRunning;
    bool m_forcePortReuse;
    QHostAddress m_relayAddress;

    // 统计和状态
    int m_totalRequests;
    int m_totalResponses;
    QMap<QByteArray, RequestInfo> m_recentRequests;

    // 定时器
    QTimer *m_cleanupTimer;
    QTimer *m_allocationTimer;
    QTimer *m_testTimer;
    QTimer *m_selectionTimer;

    // TURN分配管理
    QMap<QString, QSharedPointer<Allocation>> m_allocations;
    QMap<QPair<QString, quint16>, QString> m_relayMapping;
    QSet<quint16> m_usedRelayPorts;
    int m_maxAllocations;

    // 认证配置
    QString m_realm;
    QMap<QString, QString> m_users;

    // 中继服务器管理
    QVector<RelayServer> m_relayServers;
    QMap<QString, RelayTestResult> m_testResults;

    // 多路径测试
    QVector<PathTestConfig> m_testConfigs;
    QMap<QString, PathTestResult> m_pathTestResults;
    int m_completedTests;
    bool m_multiPathTestInProgress;

    // 测试状态
    int m_currentTestIndex;
    int m_currentPacketSeq;
    QMap<QByteArray, QElapsedTimer> m_packetTimers;
    QMap<QString, QVector<qint64>> m_latencySamples;
    bool m_testInProgress;

    // 配置参数
    quint16 m_minRelayPort;
    quint16 m_maxRelayPort;
    quint32 m_defaultLifetime;
    int m_testCount;
    int m_testTimeout;
    bool m_autoSelection;
    int m_testInterval;

    // 权重配置
    double m_latencyWeight;
    double m_jitterWeight;
    double m_packetLossWeight;
    double m_priorityWeight;

    // 线程池
    QThreadPool *m_threadPool;

    // 服务器标识
    QString m_serverId;

    friend class PathTestTask;
};

// ==================== 路径测试任务类 ====================

class PathTestTask : public QRunnable {
public:
    PathTestTask(War3Nat *parent, const PathTestConfig &config);
    void run() override;

private:
    War3Nat *m_parent;
    PathTestConfig m_config;
};

#endif // WAR3NAT_H
