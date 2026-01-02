#ifndef SECURITYWATCHDOG_H
#define SECURITYWATCHDOG_H

#include <QObject>
#include <QMap>
#include <QSet>
#include <QHostAddress>
#include <QDateTime>
#include <QMutex>
#include <QTimer>

struct IpStats {
    // UDP 统计
    int udpPacketCount = 0;
    qint64 lastUdpResetTime = 0;

    // TCP 统计
    int tcpConnCount = 0;
    qint64 lastTcpResetTime = 0;

    // 封禁状态
    bool isBanned = false;
    qint64 banExpireTime = 0;
    int violationCount = 0; // 违规次数，用于计算封禁时长

    // 最后活跃时间（用于垃圾回收）
    qint64 lastActivityTime = 0;
};

class SecurityWatchdog : public QObject
{
    Q_OBJECT
public:
    explicit SecurityWatchdog(QObject *parent = nullptr);
    ~SecurityWatchdog();

    // === 核心检测接口 ===
    // 返回 false 表示应该丢弃该包
    bool checkUdpPacket(const QHostAddress &sender, int packetSize);

    // 返回 false 表示应该断开连接
    bool checkTcpConnection(const QHostAddress &sender);

    // === 管理接口 ===
    void addWhitelist(const QString &ip);
    void addBlacklist(const QString &ip);
    void unban(const QString &ip);

private:
    // 检查并执行封禁逻辑
    bool isIpBanned(const QString &ipStr, IpStats &stats, qint64 now);
    void triggerBan(const QString &ipStr, IpStats &stats, const QString &reason);
    void cleanupStaleRecords();

private:
    // === 配置参数 ===
    const int MAX_UDP_PER_SEC = 50;      // UDP 阈值：每秒 50 个包
    const int MAX_TCP_PER_MIN = 10;      // TCP 阈值：每分钟 10 次连接尝试
    const int BAN_BASE_TIME_MS = 60000;  // 基础封禁时长：1分钟
    const int CLEANUP_INTERVAL_MS = 300000; // 清理间隔：5分钟
    const int RECORD_TIMEOUT_MS = 600000;   // 记录过期时间：10分钟无活动则移除

    // === 数据存储 ===
    QMutex m_mutex; // 保证线程安全
    QMap<QString, IpStats> m_ipStats;
    QSet<QString> m_whitelist;
    QSet<QString> m_blacklist;
    QTimer *m_cleanupTimer;
};

#endif // SECURITYWATCHDOG_H
