#include "securitywatchdog.h"
#include "logger.h"
#include <QDebug>

SecurityWatchdog::SecurityWatchdog(QObject *parent) : QObject(parent)
{
    // 添加本地回环到白名单
    m_whitelist.insert("127.0.0.1");
    m_whitelist.insert("::1");

    // 定时清理过期记录，防止 Map 无限膨胀
    m_cleanupTimer = new QTimer(this);
    connect(m_cleanupTimer, &QTimer::timeout, this, &SecurityWatchdog::cleanupStaleRecords);
    m_cleanupTimer->start(CLEANUP_INTERVAL_MS);
}

SecurityWatchdog::~SecurityWatchdog()
{
}

void SecurityWatchdog::addWhitelist(const QString &ip) {
    QMutexLocker locker(&m_mutex);
    m_whitelist.insert(ip);
}

void SecurityWatchdog::addBlacklist(const QString &ip) {
    QMutexLocker locker(&m_mutex);
    m_blacklist.insert(ip);
}

bool SecurityWatchdog::checkUdpPacket(const QHostAddress &sender, int packetSize)
{
    Q_UNUSED(packetSize);

    QString ip = sender.toString();
    // 规范化 IPv6 映射的 IPv4
    if (ip.startsWith("::ffff:")) ip = ip.mid(7);

    QMutexLocker locker(&m_mutex);

    // 1. 白名单检查 (最快通过)
    if (m_whitelist.contains(ip)) return true;

    // 2. 黑名单检查 (最快拒绝)
    if (m_blacklist.contains(ip)) return false;

    qint64 now = QDateTime::currentMSecsSinceEpoch();
    IpStats &stats = m_ipStats[ip]; // 获取引用，若不存在会自动创建默认值
    stats.lastActivityTime = now;

    // 3. 检查是否已被自动封禁
    if (isIpBanned(ip, stats, now)) return false;

    // 4. UDP 频率检测 (时间窗口：1秒)
    if (now - stats.lastUdpResetTime > 1000) {
        stats.udpPacketCount = 0;
        stats.lastUdpResetTime = now;
    }

    stats.udpPacketCount++;

    if (stats.udpPacketCount > MAX_UDP_PER_SEC) {
        triggerBan(ip, stats, QString("UDP 洪水攻击 (%1 包/秒)").arg(stats.udpPacketCount));
        return false;
    }

    return true;
}

bool SecurityWatchdog::checkTcpConnection(const QHostAddress &sender)
{
    QString ip = sender.toString();
    if (ip.startsWith("::ffff:")) ip = ip.mid(7);

    QMutexLocker locker(&m_mutex);

    if (m_whitelist.contains(ip)) return true;
    if (m_blacklist.contains(ip)) return false;

    qint64 now = QDateTime::currentMSecsSinceEpoch();
    IpStats &stats = m_ipStats[ip];
    stats.lastActivityTime = now;

    if (isIpBanned(ip, stats, now)) return false;

    // 4. TCP 频率检测 (时间窗口：60秒)
    if (now - stats.lastTcpResetTime > 60000) {
        stats.tcpConnCount = 0;
        stats.lastTcpResetTime = now;
    }

    stats.tcpConnCount++;

    if (stats.tcpConnCount > MAX_TCP_PER_MIN) {
        triggerBan(ip, stats, QString("TCP 连接洪水 (%1 次/分)").arg(stats.tcpConnCount));
        return false;
    }

    return true;
}

bool SecurityWatchdog::isIpBanned(const QString &ipStr, IpStats &stats, qint64 now)
{
    if (stats.isBanned) {
        if (now < stats.banExpireTime) {
            return true; // 仍在封禁期
        } else {
            // 封禁过期，自动解封
            stats.isBanned = false;
            // ✅ 汉化日志
            LOG_INFO(QString("🔓 IP %1 已自动解封").arg(ipStr));
        }
    }
    return false;
}

void SecurityWatchdog::triggerBan(const QString &ipStr, IpStats &stats, const QString &reason)
{
    if (stats.isBanned) return; // 已经在 ban 列表中，无需重复触发

    stats.isBanned = true;
    stats.violationCount++;

    // 阶梯式封禁时长：违规次数越多，封禁越久 (1分钟, 2分钟, 4分钟...)
    int duration = BAN_BASE_TIME_MS * (1 << qMin(stats.violationCount - 1, 5));
    stats.banExpireTime = QDateTime::currentMSecsSinceEpoch() + duration;

    LOG_WARNING(QString("🛡️ [安全拦截] 封禁 IP: %1 | 时长: %2秒 | 原因: %3")
                    .arg(ipStr).arg(duration / 1000).arg(reason));
}

void SecurityWatchdog::cleanupStaleRecords()
{
    QMutexLocker locker(&m_mutex);
    qint64 now = QDateTime::currentMSecsSinceEpoch();

    auto it = m_ipStats.begin();
    while (it != m_ipStats.end()) {
        // 如果该 IP 既没有被封禁，且长时间(10分钟)没有任何活动，则移除记录节省内存
        if (!it.value().isBanned && (now - it.value().lastActivityTime > RECORD_TIMEOUT_MS)) {
            it = m_ipStats.erase(it);
        } else {
            ++it;
        }
    }
}

void SecurityWatchdog::unban(const QString &ip) {
    QMutexLocker locker(&m_mutex);
    if (m_ipStats.contains(ip)) {
        m_ipStats[ip].isBanned = false;
        m_ipStats[ip].violationCount = 0;
    }
}
