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
    void setForcePortReuse(bool reuse) { m_forcePortReuse = reuse; }

signals:
    void allocationCreated(const QString &allocationId, const QHostAddress &relayAddr, quint16 relayPort);
    void allocationRefreshed(const QString &allocationId, quint32 newLifetime);
    void allocationExpired(const QString &allocationId);

private slots:
    void onReadyRead();
    void onCleanupTimeout();
    void onAllocationExpiryCheck();

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

    // ==================== 中继数据处理 ====================
    void relayDataToPeer(const QByteArray &data, const QHostAddress &fromAddr, quint16 fromPort,
                         const QHostAddress &toAddr, quint16 toPort);
    bool validatePermission(const Allocation &allocation, const QHostAddress &peerAddr, quint16 peerPort);

    // ==================== 工具方法 ====================
    // 公共辅助方法
    QSharedPointer<Allocation> findAllocation(const QHostAddress &clientAddr, quint16 clientPort);
    QVector<STUNAttribute> parseAttributes(const QByteArray &data, int startPos = 20);
    QHostAddress parseXorAddress(const QByteArray &data, int pos, quint16 &port);

    // 数据包处理
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

    // ==================== 日志方法 ====================
    void logRequest(const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId);
    void logResponse(const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId);
    void logTURNAction(const QString &action, const QHostAddress &clientAddr, quint16 clientPort,
                       const QString &details = "");

private:
    // ==================== 成员变量 ====================

    // 网络相关
    bool m_isRunning;
    quint16 m_serverPort;
    bool m_forcePortReuse;
    QUdpSocket *m_udpSocket;
    QHostAddress m_relayAddress;

    // 统计和状态
    int m_totalRequests;
    int m_totalResponses;
    QMap<QByteArray, RequestInfo> m_recentRequests;

    // 定时器
    QTimer *m_cleanupTimer;
    QTimer *m_allocationTimer;

    // TURN分配管理
    QMap<QString, QSharedPointer<Allocation>> m_allocations;
    QMap<QPair<QString, quint16>, QString> m_relayMapping;
    QSet<quint16> m_usedRelayPorts;
    int m_maxAllocations;

    // 认证配置
    QString m_realm;
    QMap<QString, QString> m_users;

    // 配置参数
    quint16 m_minRelayPort;
    quint16 m_maxRelayPort;
    quint32 m_defaultLifetime;

    // 线程池
    QThreadPool *m_threadPool;

    // 服务器标识
    QString m_serverId;
};

#endif // WAR3NAT_H
