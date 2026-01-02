#include "securitywatchdog.h"
#include "logger.h"
#include <QDebug>
#include <QtMath> // for qMin

SecurityWatchdog::SecurityWatchdog(QObject *parent) : QObject(parent)
{
    // 初始化默认白名单
    addWhitelist("127.0.0.1");
    addWhitelist("::1");

    m_cleanupTimer = new QTimer(this);
    connect(m_cleanupTimer, &QTimer::timeout, this, &SecurityWatchdog::cleanupStaleRecords);
    m_cleanupTimer->start(CLEANUP_INTERVAL_MS);
}

SecurityWatchdog::~SecurityWatchdog()
{
}

quint32 SecurityWatchdog::parseIpToInt(const QString &ip) const {
    QHostAddress addr(ip);
    return addr.toIPv4Address(); // 如果不是 IPv4 会返回 0
}

void SecurityWatchdog::addWhitelist(const QString &ip) {
    QMutexLocker locker(&m_mutex);

    // 同时存入 String 表和 Int 表(如果是IPv4)
    m_whitelistStr.insert(ip);

    quint32 ipInt = parseIpToInt(ip);
    if (ipInt != 0) {
        m_whitelistInt.insert(ipInt);
    }
}

void SecurityWatchdog::addBlacklist(const QString &ip) {
    QMutexLocker locker(&m_mutex);

    m_blacklistStr.insert(ip);

    quint32 ipInt = parseIpToInt(ip);
    if (ipInt != 0) {
        m_blacklistInt.insert(ipInt);
    }
}

void SecurityWatchdog::unban(const QString &ip) {
    QMutexLocker locker(&m_mutex);

    quint32 ipInt = parseIpToInt(ip);
    if (ipInt != 0) {
        if (m_ipStats.contains(ipInt)) {
            m_ipStats[ipInt].isBanned = false;
            m_ipStats[ipInt].violationCount = 0;
            LOG_INFO(QString("🔓 [手动解封] IP: %1").arg(ip));
        }
    } else {
        if (m_ipStatsFallback.contains(ip)) {
            m_ipStatsFallback[ip].isBanned = false;
            m_ipStatsFallback[ip].violationCount = 0;
            LOG_INFO(QString("🔓 [手动解封] IP: %1").arg(ip));
        }
    }
}

// ==================== 核心检查逻辑 ====================

bool SecurityWatchdog::checkUdpPacket(const QHostAddress &sender, int packetSize)
{
    Q_UNUSED(packetSize);

    // 1. 尝试获取 IPv4 整数 (极速)
    // toIPv4Address 会自动处理 ::ffff:192.168.1.1 这种映射地址
    quint32 ipv4 = sender.toIPv4Address();

    QMutexLocker locker(&m_mutex);

    // ================= [IPv4 高速路径] =================
    if (ipv4 != 0) {
        // 白名单检查 (O(1) 整数查找)
        if (m_whitelistInt.contains(ipv4)) return true;
        // 黑名单检查
        if (m_blacklistInt.contains(ipv4)) return false;

        // 内存保护：防止 IP Spoofing 填满内存
        if (!m_ipStats.contains(ipv4) && m_ipStats.size() >= MAX_IP_STATS_SIZE) {
            // 策略：内存满时，拒绝新 IP，或者允许但不记录
            // 这里选择直接拒绝，保护服务器
            return false;
        }

        IpStats &stats = m_ipStats[ipv4]; // 获取或创建
        qint64 now = QDateTime::currentMSecsSinceEpoch();
        stats.lastActivityTime = now;

        // 只有需要打印日志时，才转换 IP 为字符串，节省性能
        if (isIpBanned(ipv4, "", stats, now)) return false;

        // UDP 频率检测 (1秒窗口)
        if (now - stats.lastUdpResetTime > 1000) {
            stats.udpPacketCount = 0;
            stats.lastUdpResetTime = now;
        }

        stats.udpPacketCount++;

        if (stats.udpPacketCount > MAX_UDP_PER_SEC) {
            QString ipStr = QHostAddress(ipv4).toString(); // 仅在违规时转换
            triggerBan(ipv4, ipStr, stats, QString("UDP 洪水攻击 (%1 包/秒)").arg(stats.udpPacketCount));
            return false;
        }
        return true;
    }

    // War3 主要是 IPv4，这里作为兼容性保留
    QString ipStr = sender.toString();
    if (m_whitelistStr.contains(ipStr)) return true;
    if (m_blacklistStr.contains(ipStr)) return false;

    if (!m_ipStatsFallback.contains(ipStr) && m_ipStatsFallback.size() >= (MAX_IP_STATS_SIZE / 10)) {
        return false;
    }

    IpStats &stats = m_ipStatsFallback[ipStr];
    qint64 now = QDateTime::currentMSecsSinceEpoch();
    stats.lastActivityTime = now;

    if (isIpBanned(0, ipStr, stats, now)) return false;

    if (now - stats.lastUdpResetTime > 1000) {
        stats.udpPacketCount = 0;
        stats.lastUdpResetTime = now;
    }
    stats.udpPacketCount++;

    if (stats.udpPacketCount > MAX_UDP_PER_SEC) {
        triggerBan(0, ipStr, stats, QString("UDP 洪水 (IPv6)"));
        return false;
    }

    return true;
}

bool SecurityWatchdog::checkTcpConnection(const QHostAddress &sender)
{
    quint32 ipv4 = sender.toIPv4Address();
    QMutexLocker locker(&m_mutex);

    // ================= [IPv4 高速路径] =================
    if (ipv4 != 0) {
        if (m_whitelistInt.contains(ipv4)) return true;
        if (m_blacklistInt.contains(ipv4)) return false;

        if (!m_ipStats.contains(ipv4) && m_ipStats.size() >= MAX_IP_STATS_SIZE) return false;

        IpStats &stats = m_ipStats[ipv4];
        qint64 now = QDateTime::currentMSecsSinceEpoch();
        stats.lastActivityTime = now;

        if (isIpBanned(ipv4, "", stats, now)) return false;

        // TCP 频率检测 (60秒窗口)
        if (now - stats.lastTcpResetTime > 60000) {
            stats.tcpConnCount = 0;
            stats.lastTcpResetTime = now;
        }

        stats.tcpConnCount++;

        if (stats.tcpConnCount > MAX_TCP_PER_MIN) {
            QString ipStr = QHostAddress(ipv4).toString();
            triggerBan(ipv4, ipStr, stats, QString("TCP 连接洪水 (%1 次/分)").arg(stats.tcpConnCount));
            return false;
        }
        return true;
    }

    // ================= [IPv6 慢速路径] =================
    QString ipStr = sender.toString();
    if (m_whitelistStr.contains(ipStr)) return true;
    if (m_blacklistStr.contains(ipStr)) return false;

    IpStats &stats = m_ipStatsFallback[ipStr];
    qint64 now = QDateTime::currentMSecsSinceEpoch();
    stats.lastActivityTime = now;

    if (isIpBanned(0, ipStr, stats, now)) return false;

    if (now - stats.lastTcpResetTime > 60000) {
        stats.tcpConnCount = 0;
        stats.lastTcpResetTime = now;
    }
    stats.tcpConnCount++;
    if (stats.tcpConnCount > MAX_TCP_PER_MIN) {
        triggerBan(0, ipStr, stats, "TCP 连接洪水 (IPv6)");
        return false;
    }

    return true;
}

// ==================== 内部辅助逻辑 ====================

bool SecurityWatchdog::isIpBanned(quint32 ipInt, const QString& ipStr, IpStats &stats, qint64 now)
{
    if (stats.isBanned) {
        if (now < stats.banExpireTime) {
            return true; // 仍在封禁期
        } else {
            // 封禁过期，自动解封
            stats.isBanned = false;
            stats.udpPacketCount = 0; // 重置计数
            stats.tcpConnCount = 0;

            // 懒加载 IP 字符串：只有需要打印日志时才转换
            QString displayIp = ipStr;
            if (displayIp.isEmpty() && ipInt != 0) {
                displayIp = QHostAddress(ipInt).toString();
            }
            LOG_INFO(QString("🔓 IP %1 已自动解封").arg(displayIp));
        }
    }
    return false;
}

void SecurityWatchdog::triggerBan(quint32 ipInt, const QString& ipStr, IpStats &stats, const QString &reason)
{
    if (stats.isBanned) return;

    stats.isBanned = true;
    stats.violationCount++;

    // 阶梯式封禁：1分钟 -> 2分钟 -> 4分钟 -> 8分钟 -> ... Max 32分钟
    int duration = BAN_BASE_TIME_MS * (1 << qMin(stats.violationCount - 1, 5));
    stats.banExpireTime = QDateTime::currentMSecsSinceEpoch() + duration;

    QString displayIp = ipStr;
    if (displayIp.isEmpty() && ipInt != 0) {
        displayIp = QHostAddress(ipInt).toString();
    }

    LOG_WARNING(QString("🛡️ [安全拦截] 封禁 IP: %1 | 时长: %2秒 | 原因: %3")
                    .arg(displayIp).arg(duration / 1000).arg(reason));
}

void SecurityWatchdog::cleanupStaleRecords()
{
    QMutexLocker locker(&m_mutex);
    qint64 now = QDateTime::currentMSecsSinceEpoch();

    // 1. 清理 IPv4 表 (分批处理)
    int count = 0;
    auto it = m_ipStats.begin();
    while (it != m_ipStats.end() && count < CLEANUP_BATCH_SIZE) {
        // 如果未封禁 且 超过10分钟无活动
        if (!it.value().isBanned && (now - it.value().lastActivityTime > RECORD_TIMEOUT_MS)) {
            it = m_ipStats.erase(it);
        } else {
            ++it;
        }
        count++;
    }

    // 2. 清理 IPv6 备用表
    auto itStr = m_ipStatsFallback.begin();
    while (itStr != m_ipStatsFallback.end() && count < CLEANUP_BATCH_SIZE * 2) {
        if (!itStr.value().isBanned && (now - itStr.value().lastActivityTime > RECORD_TIMEOUT_MS)) {
            itStr = m_ipStatsFallback.erase(itStr);
        } else {
            ++itStr;
        }
        count++;
    }
}
