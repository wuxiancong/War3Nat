#ifndef SECURITYWATCHDOG_H
#define SECURITYWATCHDOG_H

#include <QObject>
#include <QHostAddress>
#include <QDateTime>
#include <QHash>
#include <QSet>
#include <QMutex>
#include <QTimer>

// ================= 配置常量 =================
// 封禁基础时长 (毫秒)
#define BAN_BASE_TIME_MS 60000
// UDP 每秒最大包数 (超过则判定为洪水)
#define MAX_UDP_PER_SEC 100
// TCP 每分钟最大连接数
#define MAX_TCP_PER_MIN 20
// 记录无活动清理时间 (10分钟)
#define RECORD_TIMEOUT_MS 600000
// 清理定时器间隔 (30秒)
#define CLEANUP_INTERVAL_MS 30000
// 最大记录数限制 (防止内存爆炸)
#define MAX_IP_STATS_SIZE 50000
// 单次清理循环最大步数 (防止锁死线程)
#define CLEANUP_BATCH_SIZE 1000

struct IpStats {
    qint64 lastActivityTime = 0;

    // UDP 统计
    qint64 lastUdpResetTime = 0;
    int udpPacketCount = 0;

    // TCP 统计
    qint64 lastTcpResetTime = 0;
    int tcpConnCount = 0;

    // 封禁状态
    bool isBanned = false;
    qint64 banExpireTime = 0;
    int violationCount = 0; // 违规次数（用于阶梯封禁）
};

class SecurityWatchdog : public QObject
{
    Q_OBJECT
public:
    explicit SecurityWatchdog(QObject *parent = nullptr);
    ~SecurityWatchdog();

    // 添加白名单 (支持字符串 IP)
    void addWhitelist(const QString &ip);
    // 添加黑名单 (支持字符串 IP)
    void addBlacklist(const QString &ip);
    // 手动解封
    void unban(const QString &ip);

    // 核心检查函数
    bool checkUdpPacket(const QHostAddress &sender, int packetSize);
    bool checkTcpConnection(const QHostAddress &sender);

private slots:
    void cleanupStaleRecords();

private:
    // 内部辅助：判断是否封禁中
    bool isIpBanned(quint32 ipInt, const QString& ipStr, IpStats &stats, qint64 now);
    // 内部辅助：触发封禁
    void triggerBan(quint32 ipInt, const QString& ipStr, IpStats &stats, const QString &reason);
    // 内部辅助：将 QString IP 转为 quint32 (仅 IPv4)
    quint32 parseIpToInt(const QString &ip) const;

private:
    QMutex m_mutex;
    QTimer *m_cleanupTimer;

    QSet<quint32> m_whitelistInt;
    QSet<quint32> m_blacklistInt;
    QSet<QString> m_whitelistStr;
    QSet<QString> m_blacklistStr;
    QHash<quint32, IpStats> m_ipStats;
    QHash<QString, IpStats> m_ipStatsFallback;
};

#endif // SECURITYWATCHDOG_H
