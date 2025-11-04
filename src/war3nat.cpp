#include "war3nat.h"
#include "logger.h"
#include <QDateTime>
#include <QDataStream>
#include <QRandomGenerator>

War3Nat::War3Nat(QObject *parent)
    : QObject(parent)
    , m_udpSocket(nullptr)
    , m_serverPort(3478)
    , m_isRunning(false)
    , m_forcePortReuse(false)
    , m_totalRequests(0)
    , m_totalResponses(0)
{
    m_cleanupTimer = new QTimer(this);
    connect(m_cleanupTimer, &QTimer::timeout, this, &War3Nat::onCleanupTimeout);
}

War3Nat::~War3Nat()
{
    stopServer();
}

bool War3Nat::startServer(quint16 port)
{
    if (m_isRunning) {
        LOG_WARNING("服务器已经在运行");
        return true;
    }

    m_serverPort = port;
    m_udpSocket = new QUdpSocket(this);

    // 设置绑定选项
    QAbstractSocket::BindMode bindMode = QUdpSocket::ShareAddress;
    if (m_forcePortReuse) {
        // 在 Qt 中，QUdpSocket::ReuseAddressHint 是一个绑定标志
        bindMode |= QUdpSocket::ReuseAddressHint;
        LOG_DEBUG("启用地址重用选项");
    }

    QHostAddress bindAddress = QHostAddress::AnyIPv4;
    if (!m_udpSocket->bind(bindAddress, m_serverPort, bindMode)) {
        LOG_CRITICAL(QString("绑定端口失败: %1").arg(m_udpSocket->errorString()));
        delete m_udpSocket;
        m_udpSocket = nullptr;
        return false;
    }

    connect(m_udpSocket, &QUdpSocket::readyRead, this, &War3Nat::onReadyRead);

    // 启动清理定时器
    m_cleanupTimer->start(30000); // 30秒清理一次

    m_isRunning = true;
    m_totalRequests = 0;
    m_totalResponses = 0;

    LOG_INFO("🎉 War3Nat STUN 服务器启动成功");
    LOG_INFO(QString("📍 监听地址: %1:%2").arg(bindAddress.toString()).arg(m_serverPort));
    LOG_INFO("💡 服务类型: STUN 服务器 (RFC 5389)");
    LOG_INFO("🔧 支持功能: NAT 类型检测、公网地址发现");
    LOG_INFO(QString("🔒 端口重用: %1").arg(m_forcePortReuse ? "启用" : "禁用"));

    return true;
}

void War3Nat::stopServer()
{
    if (m_udpSocket) {
        m_udpSocket->close();
        delete m_udpSocket;
        m_udpSocket = nullptr;
    }

    if (m_cleanupTimer) {
        m_cleanupTimer->stop();
    }

    m_isRunning = false;
    m_recentRequests.clear();

    LOG_INFO("🛑 War3Nat 服务器已停止");
    LOG_INFO(QString("📊 统计信息 - 总请求: %1, 总响应: %2").arg(m_totalRequests).arg(m_totalResponses));
}

void War3Nat::onReadyRead()
{
    if (!m_udpSocket) return;

    while (m_udpSocket->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(m_udpSocket->pendingDatagramSize());
        QHostAddress clientAddr;
        quint16 clientPort;

        qint64 bytesRead = m_udpSocket->readDatagram(datagram.data(), datagram.size(), &clientAddr, &clientPort);

        if (bytesRead > 0) {
            LOG_DEBUG(QString("📨 收到来自 %1:%2 的数据, 大小: %3 字节")
                          .arg(clientAddr.toString())
                          .arg(clientPort)
                          .arg(bytesRead));

            handleSTUNRequest(datagram, clientAddr, clientPort);
        }
    }
}

void War3Nat::handleSTUNRequest(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort)
{
    m_totalRequests++;

    // 检查是否是STUN Binding Request
    if (data.size() < 20) {
        LOG_WARNING(QString("数据包太小 (%1 字节)，不是有效的STUN请求").arg(data.size()));
        return;
    }

    // 解析STUN消息头
    quint16 messageType = (static_cast<quint8>(data[0]) << 8) | static_cast<quint8>(data[1]);
    quint16 messageLength = (static_cast<quint8>(data[2]) << 8) | static_cast<quint8>(data[3]);
    quint32 magicCookie = (static_cast<quint8>(data[4]) << 24) |
                          (static_cast<quint8>(data[5]) << 16) |
                          (static_cast<quint8>(data[6]) << 8) |
                          static_cast<quint8>(data[7]);

    QByteArray transactionId = data.mid(8, 12);

    // 验证消息长度
    if (data.size() < 20 + messageLength) {
        LOG_WARNING(QString("STUN消息长度不匹配: 声明长度=%1, 实际长度=%2")
                        .arg(messageLength)
                        .arg(data.size() - 20));
        return;
    }

    // 验证Magic Cookie
    if (magicCookie != 0x2112A442) {
        LOG_WARNING(QString("无效的STUN Magic Cookie: 0x%1").arg(magicCookie, 8, 16, QLatin1Char('0')));
        return;
    }

    // 只处理Binding Request (0x0001)
    if (messageType == 0x0001) {
        LOG_DEBUG(QString("处理STUN绑定请求 - 消息长度: %1 字节").arg(messageLength));
        logRequest(clientAddr, clientPort, transactionId);

        QByteArray response = buildSTUNResponse(data, clientAddr, clientPort);
        qint64 bytesSent = m_udpSocket->writeDatagram(response, clientAddr, clientPort);

        if (bytesSent > 0) {
            m_totalResponses++;
            logResponse(clientAddr, clientPort, transactionId);
            LOG_DEBUG(QString("📤 发送STUN响应到 %1:%2, 大小: %3 字节")
                          .arg(clientAddr.toString())
                          .arg(clientPort)
                          .arg(bytesSent));
        } else {
            LOG_ERROR(QString("发送STUN响应失败: %1").arg(m_udpSocket->errorString()));
        }
    } else {
        LOG_WARNING(QString("未知的STUN消息类型: 0x%1, 长度: %2 字节")
                        .arg(messageType, 4, 16, QLatin1Char('0'))
                        .arg(messageLength));
    }
}

QByteArray War3Nat::buildSTUNResponse(const QByteArray &request, const QHostAddress &clientAddr, quint16 clientPort)
{
    // 从请求中提取事务ID
    QByteArray transactionId = request.mid(8, 12);

    QByteArray response;
    QDataStream stream(&response, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::BigEndian);

    // STUN消息头
    stream << quint16(0x0101); // Binding Success Response
    stream << quint16(12);     // 属性长度 (只有XOR-MAPPED-ADDRESS)
    stream << quint32(0x2112A442); // Magic Cookie
    stream.writeRawData(transactionId.constData(), 12); // Transaction ID

    // XOR-MAPPED-ADDRESS 属性 (RFC 5389)
    stream << quint16(0x0020); // Attribute Type: XOR-MAPPED-ADDRESS
    stream << quint16(8);      // Attribute Length: 8 bytes

    // 计算XOR编码的端口和地址
    quint16 xoredPort = clientPort ^ (0x2112A442 >> 16);
    quint32 ipv4 = clientAddr.toIPv4Address();
    quint32 xoredIP = ipv4 ^ 0x2112A442;

    stream << quint8(0);       // Reserved
    stream << quint8(0x01);    // Family: IPv4
    stream << xoredPort;       // X-Port
    stream << xoredIP;         // X-Address

    // 记录映射信息（用于调试）
    QHostAddress mappedAddress(xoredIP ^ 0x2112A442);
    quint16 mappedPort = xoredPort ^ (0x2112A442 >> 16);

    LOG_DEBUG(QString("🔧 STUN映射 - 客户端: %1:%2 -> 公网: %3:%4")
                  .arg(clientAddr.toString())
                  .arg(clientPort)
                  .arg(mappedAddress.toString())
                  .arg(mappedPort));

    return response;
}

void War3Nat::logRequest(const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId)
{
    QString shortTransactionId = QString(transactionId.toHex().left(16)) + "...";

    LOG_INFO(QString("✅ STUN请求 - 客户端: %1:%2 - 事务ID: %3")
                 .arg(clientAddr.toString())
                 .arg(clientPort)
                 .arg(shortTransactionId));

    // 记录最近请求（包含时间戳）
    RequestInfo info;
    info.clientAddr = clientAddr;
    info.clientPort = clientPort;
    info.timestamp = QDateTime::currentMSecsSinceEpoch();

    m_recentRequests[transactionId] = info;
}

void War3Nat::logResponse(const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId)
{
    QString shortTransactionId = QString(transactionId.toHex().left(16)) + "...";

    LOG_DEBUG(QString("📤 STUN响应 - 客户端: %1:%2 - 事务ID: %3")
                  .arg(clientAddr.toString())
                  .arg(clientPort)
                  .arg(shortTransactionId));
}

void War3Nat::onCleanupTimeout()
{
    // 清理过期的请求记录（超过5分钟）
    qint64 currentTime = QDateTime::currentMSecsSinceEpoch();
    const qint64 FIVE_MINUTES = 5 * 60 * 1000; // 5分钟

    QList<QByteArray> toRemove;

    // 遍历所有请求记录，清理过期的
    for (auto it = m_recentRequests.begin(); it != m_recentRequests.end(); ++it) {
        if (currentTime - it.value().timestamp > FIVE_MINUTES) {
            toRemove.append(it.key());
        }
    }

    int removedCount = toRemove.size();
    if (removedCount > 0) {
        for (const QByteArray &key : toRemove) {
            m_recentRequests.remove(key);
        }
        LOG_DEBUG(QString("🧹 清理了 %1 个过期请求记录 (超过5分钟)").arg(removedCount));
    }

    // 定期报告统计信息（每10次清理报告一次）
    static int cleanupCount = 0;
    cleanupCount++;

    if (cleanupCount >= 10) {
        LOG_INFO(QString("📊 服务器统计 - 总请求: %1, 总响应: %2, 活跃连接: %3")
                     .arg(m_totalRequests)
                     .arg(m_totalResponses)
                     .arg(m_recentRequests.size()));
        cleanupCount = 0;
    }
}
