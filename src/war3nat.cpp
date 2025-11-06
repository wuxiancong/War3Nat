#include "logger.h"
#include "war3nat.h"
#include <QtMath>
#include <algorithm>
#include <QDateTime>
#include <QDataStream>
#include <QRandomGenerator>
#include <QNetworkInterface>
#include <QRunnable>

War3Nat::War3Nat(QObject *parent)
    : QObject(parent)
    , m_udpSocket(nullptr)
    , m_serverPort(3478)
    , m_isRunning(false)
    , m_forcePortReuse(false)
    , m_totalRequests(0)
    , m_totalResponses(0)
    , m_cleanupTimer(new QTimer(this))
    , m_allocationTimer(new QTimer(this))
    , m_testTimer(new QTimer(this))
    , m_selectionTimer(new QTimer(this))
    , m_currentTestIndex(-1)
    , m_currentPacketSeq(0)
    , m_testInProgress(false)
    , m_minRelayPort(49152)
    , m_maxRelayPort(65535)
    , m_defaultLifetime(600)
    , m_testCount(5)
    , m_testTimeout(3000)
    , m_autoSelection(true)
    , m_latencyWeight(0.4)
    , m_jitterWeight(0.3)
    , m_packetLossWeight(0.2)
    , m_priorityWeight(0.1)
    , m_threadPool(new QThreadPool(this))
{
    connect(m_cleanupTimer, &QTimer::timeout, this, &War3Nat::onCleanupTimeout);
    connect(m_allocationTimer, &QTimer::timeout, this, &War3Nat::onAllocationExpiryCheck);
    m_testTimer->setSingleShot(true);
    connect(m_testTimer, &QTimer::timeout, this, &War3Nat::onTestTimeout);
    connect(m_selectionTimer, &QTimer::timeout, this, &War3Nat::onNextTest);
    m_relayAddress = QHostAddress::AnyIPv4;
    m_threadPool->setMaxThreadCount(10);
    // 示例用户
    m_users["testuser"] = "testpass";
    LOG_DEBUG("War3Nat STUN/TURN服务器初始化完成");
}

War3Nat::~War3Nat()
{
    stopServer();
    delete m_threadPool;
}

bool War3Nat::startServer(quint16 port)
{
    if (m_isRunning) {
        LOG_WARNING("服务器已经在运行");
        return true;
    }
    m_serverPort = port;
    m_udpSocket = new QUdpSocket(this);
    QAbstractSocket::BindMode bindMode = QUdpSocket::ShareAddress;
    if (m_forcePortReuse) {
        bindMode |= QUdpSocket::ReuseAddressHint;
        LOG_DEBUG("启用地址重用选项");
    }
    QHostAddress bindAddress = QHostAddress::Any;
    if (!m_udpSocket->bind(bindAddress, m_serverPort, bindMode)) {
        LOG_CRITICAL(QString("绑定端口失败: %1").arg(m_udpSocket->errorString()));
        delete m_udpSocket;
        m_udpSocket = nullptr;
        return false;
    }
    connect(m_udpSocket, &QUdpSocket::readyRead, this, &War3Nat::onReadyRead);
    m_cleanupTimer->start(30000);
    m_allocationTimer->start(60000);
    m_isRunning = true;
    m_totalRequests = 0;
    m_totalResponses = 0;
    m_relayAddress = m_udpSocket->localAddress();
    LOG_INFO("🎉 War3Nat STUN/TURN 服务器启动成功");
    LOG_INFO(QString("📍 监听地址: %1:%2").arg(bindAddress.toString()).arg(m_serverPort));
    LOG_INFO(QString("🔄 中继地址: %1").arg(m_relayAddress.toString()));
    LOG_INFO("💡 服务类型: STUN服务器 (RFC 5389) + TURN中继 (RFC 5766)");
    LOG_INFO("🔧 支持功能: NAT类型检测、公网地址发现、数据中继、多中继选择");
    LOG_INFO(QString("🔒 端口重用: %1").arg(m_forcePortReuse ? "启用" : "禁用"));
    LOG_INFO(QString("🔄 中继端口范围: %1-%2").arg(m_minRelayPort).arg(m_maxRelayPort));
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
    if (m_allocationTimer) {
        m_allocationTimer->stop();
    }
    if (m_testTimer) {
        m_testTimer->stop();
    }
    if (m_selectionTimer) {
        m_selectionTimer->stop();
    }
    m_isRunning = false;
    m_recentRequests.clear();
    m_allocations.clear();
    m_relayMapping.clear();
    m_usedRelayPorts.clear();
    m_testResults.clear();
    m_latencySamples.clear();
    m_packetTimers.clear();
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
            m_totalRequests++;
            LOG_DEBUG(QString("📨 收到来自 %1:%2 的数据, 大小: %3 字节")
                          .arg(clientAddr.toString())
                          .arg(clientPort)
                          .arg(bytesRead));
            // 使用线程池异步处理
            m_threadPool->start([this, datagram, clientAddr, clientPort]() {
                if (datagram.size() >= 20) {
                    quint16 messageType = (static_cast<quint8>(datagram[0]) << 8) | static_cast<quint8>(datagram[1]);
                    quint32 magicCookie = (static_cast<quint8>(datagram[4]) << 24) |
                                          (static_cast<quint8>(datagram[5]) << 16) |
                                          (static_cast<quint8>(datagram[6]) << 8) |
                                          static_cast<quint8>(datagram[7]);
                    if (magicCookie == 0x2112A442) {
                        if (messageType == STUN_BINDING_REQUEST) {
                            handleSTUNRequest(datagram, clientAddr, clientPort);
                        } else if (messageType >= 0x0003 && messageType <= 0x0009) {
                            handleTURNRequest(datagram, clientAddr, clientPort);
                        } else {
                            LOG_WARNING(QString("未知的STUN/TURN消息类型: 0x%1").arg(messageType, 4, 16, QLatin1Char('0')));
                        }
                    } else {
                        processTestResponse(datagram);
                    }
                }
            });
        }
    }
}

void War3Nat::handleSTUNRequest(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort)
{
    if (data.size() < 20) {
        LOG_WARNING(QString("数据包太小 (%1 字节)，不是有效的STUN请求").arg(data.size()));
        return;
    }
    quint16 messageType = (static_cast<quint8>(data[0]) << 8) | static_cast<quint8>(data[1]);
    quint16 messageLength = (static_cast<quint8>(data[2]) << 8) | static_cast<quint8>(data[3]);
    quint32 magicCookie = (static_cast<quint8>(data[4]) << 24) |
                          (static_cast<quint8>(data[5]) << 16) |
                          (static_cast<quint8>(data[6]) << 8) |
                          static_cast<quint8>(data[7]);
    QByteArray transactionId = data.mid(8, 12);
    if (data.size() < 20 + messageLength) {
        LOG_WARNING(QString("STUN消息长度不匹配: 声明长度=%1, 实际长度=%2")
                        .arg(messageLength)
                        .arg(data.size() - 20));
        return;
    }
    if (magicCookie != 0x2112A442) {
        LOG_WARNING(QString("无效的STUN Magic Cookie: 0x%1").arg(magicCookie, 8, 16, QLatin1Char('0')));
        return;
    }
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
    QByteArray transactionId = request.mid(8, 12);
    QByteArray response;
    QDataStream stream(&response, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::BigEndian);
    stream << quint16(0x0101);
    stream << quint16(12);
    stream << quint32(0x2112A442);
    stream.writeRawData(transactionId.constData(), 12);
    stream << quint16(0x0020);
    stream << quint16(8);
    quint16 xoredPort = clientPort ^ (0x2112A442 >> 16);
    quint32 ipv4 = clientAddr.toIPv4Address();
    quint32 xoredIP = ipv4 ^ 0x2112A442;
    stream << quint8(0);
    stream << quint8(0x01);
    stream << xoredPort;
    stream << xoredIP;
    QHostAddress mappedAddress(xoredIP ^ 0x2112A442);
    quint16 mappedPort = xoredPort ^ (0x2112A442 >> 16);
    LOG_DEBUG(QString("🔧 STUN映射 - 客户端: %1:%2 -> 公网: %3:%4")
                  .arg(clientAddr.toString())
                  .arg(clientPort)
                  .arg(mappedAddress.toString())
                  .arg(mappedPort));
    return response;
}

void War3Nat::handleTURNRequest(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort)
{
    if (data.size() < 20) {
        LOG_WARNING("TURN请求数据太小");
        return;
    }
    quint16 messageType = (static_cast<quint8>(data[0]) << 8) | static_cast<quint8>(data[1]);
    QByteArray transactionId = data.mid(8, 12);
    logRequest(clientAddr, clientPort, transactionId);
    switch (messageType) {
    case TURN_ALLOCATE_REQUEST:
        handleAllocateRequest(data, clientAddr, clientPort, transactionId);
        break;
    case TURN_REFRESH_REQUEST:
        handleRefreshRequest(data, clientAddr, clientPort, transactionId);
        break;
    case TURN_CREATE_PERMISSION:
        handleCreatePermission(data, clientAddr, clientPort, transactionId);
        break;
    case TURN_CHANNEL_BIND:
        handleChannelBind(data, clientAddr, clientPort, transactionId);
        break;
    case TURN_SEND_INDICATION:
        handleSendIndication(data, clientAddr, clientPort);
        break;
    default:
        LOG_WARNING(QString("不支持的TURN消息类型: 0x%1").arg(messageType, 4, 16, QLatin1Char('0')));
        break;
    }
}

void War3Nat::handleAllocateRequest(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId)
{
    QString username;
    if (!authenticateRequest(data, transactionId, username, clientAddr, clientPort)) {
        QByteArray error = buildErrorResponse(transactionId, 401, "Unauthorized");
        m_udpSocket->writeDatagram(error, clientAddr, clientPort);
        return;
    }
    if (m_allocations.size() >= m_maxAllocations) {
        QByteArray error = buildErrorResponse(transactionId, 413, "Request Too Large");
        m_udpSocket->writeDatagram(error, clientAddr, clientPort);
        return;
    }
    LOG_INFO(QString("🔄 TURN分配请求来自 %1:%2").arg(clientAddr.toString()).arg(clientPort));
    quint16 requestedTransport = 17;
    bool evenPortRequested = false;
    int pos = 20;
    while (pos + 4 <= data.size()) {
        quint16 attributeType = (static_cast<quint8>(data[pos]) << 8) | static_cast<quint8>(data[pos+1]);
        quint16 attributeLength = (static_cast<quint8>(data[pos+2]) << 8) | static_cast<quint8>(data[pos+3]);
        if (pos + 4 + attributeLength > data.size()) {
            break;
        }
        switch (attributeType) {
        case TURN_ATTR_REQUESTED_TRANSPORT:
            if (attributeLength >= 4) {
                requestedTransport = static_cast<quint8>(data[pos+5]);
                LOG_DEBUG(QString("请求的传输协议: %1").arg(requestedTransport));
            }
            break;
        case TURN_ATTR_EVEN_PORT:
            if (attributeLength >= 1) {
                evenPortRequested = (static_cast<quint8>(data[pos+4]) & 0x80) != 0;
                LOG_DEBUG(QString("偶数端口请求: %1").arg(evenPortRequested ? "是" : "否"));
            }
            break;
        case TURN_ATTR_DONT_FRAGMENT:
            LOG_DEBUG("不分片标志设置");
            break;
        default:
            break;
        }
        pos += 4 + attributeLength;
        if (attributeLength % 4 != 0) {
            pos += 4 - (attributeLength % 4);
        }
    }
    if (requestedTransport != 17) {
        LOG_WARNING(QString("不支持的传输协议: %1，只支持UDP(17)").arg(requestedTransport));
        QByteArray errorResponse = buildErrorResponse(transactionId, 442, "Unsupported Transport Protocol");
        m_udpSocket->writeDatagram(errorResponse, clientAddr, clientPort);
        return;
    }
    QString allocationId = QString("%1_%2_%3").arg(clientAddr.toString()).arg(clientPort).arg(QRandomGenerator::global()->generate());
    if (m_allocations.contains(allocationId)) {
        LOG_WARNING("客户端已存在分配，发送错误响应");
        QByteArray errorResponse = buildErrorResponse(transactionId, 437, "Allocation Mismatch");
        m_udpSocket->writeDatagram(errorResponse, clientAddr, clientPort);
        return;
    }
    QHostAddress relayAddr = allocateRelayAddress();
    quint16 relayPort = allocateRelayPort(evenPortRequested);
    if (relayPort == 0) {
        LOG_ERROR("无法分配中继端口，端口耗尽");
        QByteArray errorResponse = buildErrorResponse(transactionId, 508, "Insufficient Capacity");
        m_udpSocket->writeDatagram(errorResponse, clientAddr, clientPort);
        return;
    }
    Allocation *alloc = new Allocation;
    alloc->allocationId = allocationId;
    alloc->clientAddr = clientAddr;
    alloc->clientPort = clientPort;
    alloc->relayAddr = relayAddr;
    alloc->relayPort = relayPort;
    alloc->expiryTime = QDateTime::currentDateTime().addSecs(m_defaultLifetime);
    alloc->lifetime = m_defaultLifetime;
    alloc->username = username;
    m_allocations[allocationId] = QSharedPointer<Allocation>(alloc);
    m_relayMapping[qMakePair(relayAddr.toString(), relayPort)] = allocationId;
    m_usedRelayPorts.insert(relayPort);
    QByteArray response = buildAllocateResponse(transactionId, relayAddr, relayPort, m_defaultLifetime);
    m_udpSocket->writeDatagram(response, clientAddr, clientPort);
    m_totalResponses++;
    logTURNAction("ALLOCATE", clientAddr, clientPort,
                  QString("分配ID: %1, 中继地址: %2:%3, 传输协议: UDP, 过期时间: %4")
                      .arg(allocationId)
                      .arg(relayAddr.toString()).arg(relayPort)
                      .arg(alloc->expiryTime.toString("hh:mm:ss")));
    emit allocationCreated(allocationId, relayAddr, relayPort);
}

void War3Nat::handleRefreshRequest(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId)
{
    LOG_INFO(QString("🔄 TURN刷新请求来自 %1:%2").arg(clientAddr.toString()).arg(clientPort));
    quint32 requestedLifetime = 0;
    int pos = 20;
    while (pos + 4 <= data.size()) {
        quint16 attributeType = (static_cast<quint8>(data[pos]) << 8) | static_cast<quint8>(data[pos+1]);
        quint16 attributeLength = (static_cast<quint8>(data[pos+2]) << 8) | static_cast<quint8>(data[pos+3]);
        if (attributeType == TURN_ATTR_LIFETIME && attributeLength >= 4) {
            requestedLifetime = (static_cast<quint8>(data[pos+4]) << 24) |
                                (static_cast<quint8>(data[pos+5]) << 16) |
                                (static_cast<quint8>(data[pos+6]) << 8) |
                                static_cast<quint8>(data[pos+7]);
            break;
        }
        pos += 4 + attributeLength;
        if (attributeLength % 4 != 0) {
            pos += 4 - (attributeLength % 4);
        }
    }
    QString allocationId;
    for (auto it = m_allocations.begin(); it != m_allocations.end(); ++it) {
        if (it.value()->clientAddr == clientAddr && it.value()->clientPort == clientPort) {
            allocationId = it.key();
            break;
        }
    }
    if (allocationId.isEmpty()) {
        LOG_WARNING("刷新请求：未找到分配记录");
        QByteArray errorResponse = buildErrorResponse(transactionId, 437, "Allocation Mismatch");
        m_udpSocket->writeDatagram(errorResponse, clientAddr, clientPort);
        return;
    }
    QSharedPointer<Allocation> allocation = m_allocations[allocationId];
    quint32 newLifetime = m_defaultLifetime;
    if (requestedLifetime > 0) {
        newLifetime = qMin(requestedLifetime, m_defaultLifetime);
    }
    allocation->expiryTime = QDateTime::currentDateTime().addSecs(newLifetime);
    allocation->lifetime = newLifetime;
    QByteArray response = buildRefreshResponse(transactionId, newLifetime);
    m_udpSocket->writeDatagram(response, clientAddr, clientPort);
    m_totalResponses++;
    logTURNAction("REFRESH", clientAddr, clientPort,
                  QString("分配ID: %1, 新生命周期: %2秒").arg(allocationId).arg(newLifetime));
    emit allocationRefreshed(allocationId, newLifetime);
}

void War3Nat::handleCreatePermission(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId)
{
    LOG_INFO(QString("🔄 TURN创建权限请求来自 %1:%2").arg(clientAddr.toString()).arg(clientPort));
    QHostAddress peerAddr;
    quint16 peerPort = 0;
    int pos = 20;
    while (pos + 4 <= data.size()) {
        quint16 attributeType = (static_cast<quint8>(data[pos]) << 8) | static_cast<quint8>(data[pos+1]);
        quint16 attributeLength = (static_cast<quint8>(data[pos+2]) << 8) | static_cast<quint8>(data[pos+3]);
        if (attributeType == TURN_ATTR_XOR_PEER_ADDRESS && attributeLength >= 8) {
            quint16 xoredPort = (static_cast<quint8>(data[pos+6]) << 8) | static_cast<quint8>(data[pos+7]);
            peerPort = xoredPort ^ (0x2112A442 >> 16);
            quint32 xoredIP = (static_cast<quint8>(data[pos+8]) << 24) |
                              (static_cast<quint8>(data[pos+9]) << 16) |
                              (static_cast<quint8>(data[pos+10]) << 8) |
                              static_cast<quint8>(data[pos+11]);
            quint32 ip = xoredIP ^ 0x2112A442;
            peerAddr = QHostAddress(ip);
            break;
        }
        pos += 4 + attributeLength;
        if (attributeLength % 4 != 0) {
            pos += 4 - (attributeLength % 4);
        }
    }
    if (peerAddr.isNull() || peerPort == 0) {
        LOG_WARNING("创建权限请求：无效的对等端地址");
        QByteArray errorResponse = buildErrorResponse(transactionId, 400, "Bad Request");
        m_udpSocket->writeDatagram(errorResponse, clientAddr, clientPort);
        return;
    }
    QString allocationId;
    for (auto it = m_allocations.begin(); it != m_allocations.end(); ++it) {
        if (it.value()->clientAddr == clientAddr && it.value()->clientPort == clientPort) {
            allocationId = it.key();
            break;
        }
    }
    if (allocationId.isEmpty()) {
        LOG_WARNING("创建权限请求：未找到分配记录");
        QByteArray errorResponse = buildErrorResponse(transactionId, 437, "Allocation Mismatch");
        m_udpSocket->writeDatagram(errorResponse, clientAddr, clientPort);
        return;
    }
    QSharedPointer<Allocation> allocation = m_allocations[allocationId];
    allocation->permissions.insert(qMakePair(peerAddr.toString(), peerPort));
    QByteArray response = buildCreatePermissionResponse(transactionId);
    m_udpSocket->writeDatagram(response, clientAddr, clientPort);
    m_totalResponses++;
    logTURNAction("CREATE_PERMISSION", clientAddr, clientPort,
                  QString("分配ID: %1, 允许对等端: %2:%3").arg(allocationId, peerAddr.toString()).arg(peerPort));
}

void War3Nat::handleChannelBind(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId)
{
    LOG_INFO(QString("🔄 TURN通道绑定请求来自 %1:%2").arg(clientAddr.toString()).arg(clientPort));
    quint16 channelNumber = 0;
    QHostAddress peerAddr;
    quint16 peerPort = 0;
    int pos = 20;
    while (pos + 4 <= data.size()) {
        quint16 attributeType = (static_cast<quint8>(data[pos]) << 8) | static_cast<quint8>(data[pos+1]);
        quint16 attributeLength = (static_cast<quint8>(data[pos+2]) << 8) | static_cast<quint8>(data[pos+3]);
        if (attributeType == TURN_ATTR_CHANNEL_NUMBER && attributeLength >= 4) {
            channelNumber = (static_cast<quint8>(data[pos+4]) << 8) | static_cast<quint8>(data[pos+5]);
        }
        else if (attributeType == TURN_ATTR_XOR_PEER_ADDRESS && attributeLength >= 8) {
            quint16 xoredPort = (static_cast<quint8>(data[pos+6]) << 8) | static_cast<quint8>(data[pos+7]);
            peerPort = xoredPort ^ (0x2112A442 >> 16);
            quint32 xoredIP = (static_cast<quint8>(data[pos+8]) << 24) |
                              (static_cast<quint8>(data[pos+9]) << 16) |
                              (static_cast<quint8>(data[pos+10]) << 8) |
                              static_cast<quint8>(data[pos+11]);
            quint32 ip = xoredIP ^ 0x2112A442;
            peerAddr = QHostAddress(ip);
        }
        pos += 4 + attributeLength;
        if (attributeLength % 4 != 0) {
            pos += 4 - (attributeLength % 4);
        }
    }
    if (channelNumber == 0 || peerAddr.isNull() || peerPort == 0) {
        LOG_WARNING("通道绑定请求：无效的参数");
        QByteArray errorResponse = buildErrorResponse(transactionId, 400, "Bad Request");
        m_udpSocket->writeDatagram(errorResponse, clientAddr, clientPort);
        return;
    }
    QString allocationId;
    for (auto it = m_allocations.begin(); it != m_allocations.end(); ++it) {
        if (it.value()->clientAddr == clientAddr && it.value()->clientPort == clientPort) {
            allocationId = it.key();
            break;
        }
    }
    if (allocationId.isEmpty()) {
        LOG_WARNING("通道绑定请求：未找到分配记录");
        QByteArray errorResponse = buildErrorResponse(transactionId, 437, "Allocation Mismatch");
        m_udpSocket->writeDatagram(errorResponse, clientAddr, clientPort);
        return;
    }
    QSharedPointer<Allocation> allocation = m_allocations[allocationId];
    allocation->channelBindings[channelNumber] = qMakePair(peerAddr.toString(), peerPort);
    QByteArray response = buildChannelBindResponse(transactionId);
    m_udpSocket->writeDatagram(response, clientAddr, clientPort);
    m_totalResponses++;
    logTURNAction("CHANNEL_BIND", clientAddr, clientPort,
                  QString("分配ID: %1, 通道: %2, 对等端: %3:%4")
                      .arg(allocationId).arg(channelNumber)
                      .arg(peerAddr.toString()).arg(peerPort));
}

void War3Nat::handleSendIndication(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort)
{
    QString allocationId;
    for (auto it = m_allocations.begin(); it != m_allocations.end(); ++it) {
        if (it.value()->clientAddr == clientAddr && it.value()->clientPort == clientPort) {
            allocationId = it.key();
            break;
        }
    }
    if (allocationId.isEmpty() || !m_allocations.contains(allocationId)) {
        LOG_WARNING(QString("未找到分配记录: %1:%2").arg(clientAddr.toString()).arg(clientPort));
        return;
    }
    QSharedPointer<Allocation> allocation = m_allocations[allocationId];
    QHostAddress peerAddr;
    quint16 peerPort = 0;
    QByteArray relayData;
    int pos = 20;
    while (pos + 4 <= data.size()) {
        quint16 attributeType = (static_cast<quint8>(data[pos]) << 8) | static_cast<quint8>(data[pos+1]);
        quint16 attributeLength = (static_cast<quint8>(data[pos+2]) << 8) | static_cast<quint8>(data[pos+3]);
        if (attributeType == TURN_ATTR_XOR_PEER_ADDRESS && attributeLength >= 8) {
            quint16 xoredPort = (static_cast<quint8>(data[pos+6]) << 8) | static_cast<quint8>(data[pos+7]);
            peerPort = xoredPort ^ (0x2112A442 >> 16);
            quint32 xoredIP = (static_cast<quint8>(data[pos+8]) << 24) |
                              (static_cast<quint8>(data[pos+9]) << 16) |
                              (static_cast<quint8>(data[pos+10]) << 8) |
                              static_cast<quint8>(data[pos+11]);
            quint32 ip = xoredIP ^ 0x2112A442;
            peerAddr = QHostAddress(ip);
        } else if (attributeType == TURN_ATTR_DATA && attributeLength > 0) {
            relayData = data.mid(pos + 4, attributeLength);
        }
        pos += 4 + attributeLength;
        if (attributeLength % 4 != 0) {
            pos += 4 - (attributeLength % 4);
        }
    }
    if (peerAddr.isNull() || peerPort == 0 || relayData.isEmpty()) {
        LOG_WARNING("Send Indication: 无效的参数");
        return;
    }
    if (validatePermission(*allocation, peerAddr, peerPort)) {
        relayDataToPeer(relayData, allocation->relayAddr, allocation->relayPort, peerAddr, peerPort);
        logTURNAction("SEND", clientAddr, clientPort,
                      QString("数据大小: %1 字节, 到 %2:%3").arg(relayData.size()).arg(peerAddr.toString()).arg(peerPort));
    } else {
        LOG_WARNING("Send Indication: 权限验证失败");
    }
}

bool War3Nat::authenticateRequest(const QByteArray &data, const QByteArray &transactionId, QString &username, const QHostAddress &clientAddr, quint16 clientPort)
{
    Q_UNUSED(transactionId);
    Q_UNUSED(clientAddr);
    Q_UNUSED(clientPort);
    QString parsedUsername, realm, nonce;
    QByteArray integrity;
    int pos = 20;
    while (pos + 4 <= data.size()) {
        quint16 attrType = (static_cast<quint8>(data[pos]) << 8) | static_cast<quint8>(data[pos+1]);
        quint16 attrLen = (static_cast<quint8>(data[pos+2]) << 8) | static_cast<quint8>(data[pos+3]);
        if (pos + 4 + attrLen > data.size()) break;
        QByteArray attrValue = data.mid(pos + 4, attrLen);
        if (attrType == STUN_ATTR_USERNAME) {
            parsedUsername = QString::fromUtf8(attrValue);
        } else if (attrType == STUN_ATTR_REALM) {
            realm = QString::fromUtf8(attrValue);
        } else if (attrType == STUN_ATTR_NONCE) {
            nonce = QString::fromUtf8(attrValue);
        } else if (attrType == STUN_ATTR_MESSAGE_INTEGRITY) {
            integrity = attrValue;
        }
        pos += 4 + attrLen;
        if (attrLen % 4 != 0) pos += 4 - (attrLen % 4);
    }
    if (parsedUsername.isEmpty() || integrity.isEmpty()) {
        LOG_WARNING("认证失败: 缺少用户名或完整性属性");
        return false;
    }
    if (realm != m_realm) {
        LOG_WARNING("认证失败: Realm不匹配");
        return false;
    }
    if (!m_users.contains(parsedUsername)) {
        LOG_WARNING("认证失败: 无效用户名");
        return false;
    }
    // 计算HMAC-SHA1
    QString password = m_users[parsedUsername];
    QByteArray key = QCryptographicHash::hash((parsedUsername + ":" + m_realm + ":" + password).toUtf8(), QCryptographicHash::Md5);
    // 消息是到MESSAGE-INTEGRITY属性前，包括头部
    // ATTRIBUTE start is type (2) + len (2) + value (20)
    // So, the start of MESSAGE-INTEGRITY attribute is data.size() - 24
    QByteArray message = data.left(data.size() - 24);
    QDataStream lenStream(&message, QIODevice::ReadWrite);
    lenStream.setByteOrder(QDataStream::BigEndian);
    lenStream.device()->seek(2);
    quint16 adjustedLen = message.size() - 20;
    lenStream << adjustedLen;
    QByteArray computed = hmacSha1(key, message);
    if (computed != integrity) {
        LOG_WARNING("认证失败: 消息完整性校验失败");
        return false;
    }
    username = parsedUsername;
    return true;
}

QByteArray War3Nat::hmacSha1(const QByteArray &key, const QByteArray &message)
{
    int blockSize = 64; // SHA1 block size
    QByteArray normalizedKey = key;
    if (normalizedKey.length() > blockSize) {
        normalizedKey = QCryptographicHash::hash(normalizedKey, QCryptographicHash::Sha1);
    }
    normalizedKey.append(QByteArray(blockSize - normalizedKey.length(), 0));
    QByteArray innerPadding = QByteArray(blockSize, static_cast<char>(0x36));
    QByteArray outerPadding = QByteArray(blockSize, static_cast<char>(0x5C));
    for (int i = 0; i < blockSize; ++i) {
        innerPadding[i] = static_cast<char>(static_cast<unsigned char>(innerPadding[i]) ^ static_cast<unsigned char>(normalizedKey[i]));
        outerPadding[i] = static_cast<char>(static_cast<unsigned char>(outerPadding[i]) ^ static_cast<unsigned char>(normalizedKey[i]));
    }
    QByteArray innerHash = QCryptographicHash::hash(innerPadding + message, QCryptographicHash::Sha1);
    return QCryptographicHash::hash(outerPadding + innerHash, QCryptographicHash::Sha1);
}

QByteArray War3Nat::buildAllocateResponse(const QByteArray &transactionId, const QHostAddress &relayAddr, quint16 relayPort, quint32 lifetime)
{
    QByteArray response;
    QDataStream stream(&response, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::BigEndian);
    stream << quint16(0x0103);
    stream << quint16(32);
    stream << quint32(0x2112A442);
    stream.writeRawData(transactionId.constData(), 12);
    stream << quint16(TURN_ATTR_XOR_RELAYED_ADDRESS);
    stream << quint16(8);
    quint16 xoredPort = relayPort ^ (0x2112A442 >> 16);
    quint32 xoredIP = relayAddr.toIPv4Address() ^ 0x2112A442;
    stream << quint8(0);
    stream << quint8(0x01);
    stream << xoredPort;
    stream << xoredIP;
    stream << quint16(TURN_ATTR_LIFETIME);
    stream << quint16(4);
    stream << lifetime;
    return response;
}

QByteArray War3Nat::buildRefreshResponse(const QByteArray &transactionId, quint32 lifetime)
{
    QByteArray response;
    QDataStream stream(&response, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::BigEndian);
    stream << quint16(0x0104);
    stream << quint16(4);
    stream << quint32(0x2112A442);
    stream.writeRawData(transactionId.constData(), 12);
    stream << quint16(TURN_ATTR_LIFETIME);
    stream << quint16(4);
    stream << lifetime;
    return response;
}

QByteArray War3Nat::buildCreatePermissionResponse(const QByteArray &transactionId)
{
    QByteArray response;
    QDataStream stream(&response, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::BigEndian);
    stream << quint16(0x0108);
    stream << quint16(0);
    stream << quint32(0x2112A442);
    stream.writeRawData(transactionId.constData(), 12);
    return response;
}

QByteArray War3Nat::buildChannelBindResponse(const QByteArray &transactionId)
{
    QByteArray response;
    QDataStream stream(&response, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::BigEndian);
    stream << quint16(0x0109);
    stream << quint16(0);
    stream << quint32(0x2112A442);
    stream.writeRawData(transactionId.constData(), 12);
    return response;
}

QByteArray War3Nat::buildErrorResponse(const QByteArray &transactionId, quint16 errorCode, const QString &reason)
{
    QByteArray reasonBytes = reason.toUtf8();
    int reasonLen = reasonBytes.size();
    int padding = (4 - reasonLen % 4) % 4;
    int attrLen = 4 + reasonLen + padding;
    QByteArray response;
    QDataStream stream(&response, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::BigEndian);
    stream << quint16(0x0111);
    stream << quint16(attrLen);
    stream << quint32(0x2112A442);
    stream.writeRawData(transactionId.constData(), 12);
    stream << quint16(STUN_ATTR_ERROR_CODE);
    stream << quint16(4 + reasonLen);
    stream << quint16(0);
    stream << quint8(errorCode / 100);
    stream << quint8(errorCode % 100);
    stream.writeRawData(reasonBytes.constData(), reasonLen);
    for (int i = 0; i < padding; ++i) {
        stream << quint8(0);
    }
    return response;
}

bool War3Nat::validatePermission(const Allocation &allocation, const QHostAddress &peerAddr, quint16 peerPort)
{
    return allocation.permissions.contains(qMakePair(peerAddr.toString(), peerPort));
}

void War3Nat::relayDataToPeer(const QByteArray &data, const QHostAddress &fromAddr, quint16 fromPort,
                              const QHostAddress &toAddr, quint16 toPort)
{
    qint64 bytesSent = m_udpSocket->writeDatagram(data, toAddr, toPort);
    if (bytesSent > 0) {
        LOG_DEBUG(QString("📤 中继数据从 %1:%2 到 %3:%4, 大小: %5 字节")
                      .arg(fromAddr.toString()).arg(fromPort)
                      .arg(toAddr.toString()).arg(toPort)
                      .arg(bytesSent));
    } else {
        LOG_ERROR(QString("中继数据失败: %1").arg(m_udpSocket->errorString()));
    }
}

void War3Nat::addRelayServer(const RelayServer &server)
{
    for (int i = 0; i < m_relayServers.size(); ++i) {
        if (m_relayServers[i].id == server.id) {
            m_relayServers[i] = server;
            LOG_INFO(QString("更新中继服务器: %1").arg(server.name));
            return;
        }
    }
    m_relayServers.append(server);
    LOG_INFO(QString("添加中继服务器: %1 (%2:%3)").arg(server.name, server.address.toString()).arg(server.port));
}

void War3Nat::removeRelayServer(const QString &serverId)
{
    m_relayServers.erase(std::remove_if(m_relayServers.begin(), m_relayServers.end(),
                                        [&](const RelayServer& server) { return server.id == serverId; }),
                         m_relayServers.end());
}

void War3Nat::setRelayServers(const QVector<RelayServer> &servers)
{
    m_relayServers = servers;
    LOG_INFO(QString("设置中继服务器列表: %1 个服务器").arg(servers.size()));
}

QVector<RelayServer> War3Nat::getRelayServers() const
{
    return m_relayServers;
}

void War3Nat::startRelaySelection()
{
    if (m_relayServers.isEmpty()) {
        LOG_WARNING("没有可用的中继服务器");
        return;
    }
    if (m_testInProgress) {
        LOG_WARNING("中继选择测试正在进行中");
        return;
    }
    m_testInProgress = true;
    m_currentTestIndex = 0;
    m_testResults.clear();
    m_latencySamples.clear();
    m_packetTimers.clear();
    LOG_INFO("🚀 开始中继服务器选择测试");
    LOG_INFO(QString("测试服务器数量: %1, 每个服务器测试包: %2").arg(m_relayServers.size()).arg(m_testCount));
    emit relaySelectionStarted();
    performRelayTest(m_relayServers.first());
}

void War3Nat::stopRelaySelection()
{
    if (m_testInProgress) {
        m_testInProgress = false;
        m_testTimer->stop();
        m_selectionTimer->stop();
        LOG_INFO("🛑 中继选择测试已停止");
    }
}

RelayServer War3Nat::getOptimalRelay() const
{
    RelayServer optimal;
    int bestScore = -1;
    for (const RelayServer &server : m_relayServers) {
        if (!server.enabled) continue;
        if (m_testResults.contains(server.id)) {
            const RelayTestResult &result = m_testResults[server.id];
            if (result.reachable && result.score > bestScore) {
                bestScore = result.score;
                optimal = server;
                optimal.latency = result.latency;
                optimal.jitter = result.jitter;
                optimal.packetLoss = result.packetLoss;
                optimal.score = result.score;
            }
        }
    }
    return optimal;
}

QVector<RelayTestResult> War3Nat::getTestResults() const
{
    return m_testResults.values().toVector();
}

void War3Nat::performRelayTest(const RelayServer &server)
{
    if (!server.enabled) {
        LOG_DEBUG(QString("跳过禁用服务器: %1").arg(server.name));
        emit relayTestProgress(server.id, 100);
        onNextTest();
        return;
    }
    LOG_DEBUG(QString("开始测试服务器: %1 (%2:%3)").arg(server.name, server.address.toString()).arg(server.port));
    m_currentPacketSeq = 0;
    m_latencySamples[server.id].clear();
    sendTestPacket(server, 0);
}

void War3Nat::sendTestPacket(const RelayServer &server, int seq)
{
    QByteArray testPacket = createTestPacket(seq, server.id.toUtf8());
    QElapsedTimer timer;
    timer.start();
    m_packetTimers[testPacket] = timer;
    qint64 bytesSent = m_udpSocket->writeDatagram(testPacket, server.address, server.port);
    if (bytesSent > 0) {
        LOG_DEBUG(QString("发送测试包到 %1, 序列: %2, 大小: %3 字节")
                      .arg(server.name).arg(seq).arg(bytesSent));
        m_testTimer->start(m_testTimeout);
        int progress = (seq * 100) / m_testCount;
        emit relayTestProgress(server.id, progress);
    } else {
        LOG_ERROR(QString("发送测试包失败: %1").arg(m_udpSocket->errorString()));
        onTestTimeout();
    }
}

void War3Nat::processTestResponse(const QByteArray &data)
{
    int sequence;
    QByteArray serverIdBytes;
    if (!parseTestResponse(data, sequence, serverIdBytes)) {
        return;
    }
    QString serverId = QString::fromUtf8(serverIdBytes);
    QByteArray expectedPacket = createTestPacket(sequence, serverIdBytes);
    if (!m_packetTimers.contains(expectedPacket)) {
        return;
    }
    qint64 latency = m_packetTimers[expectedPacket].elapsed();
    m_packetTimers.remove(expectedPacket);
    m_latencySamples[serverId].append(latency);
    LOG_DEBUG(QString("收到测试响应 - 服务器: %1, 序列: %2, 延迟: %3ms")
                  .arg(serverId).arg(sequence).arg(latency));
    m_testTimer->stop();
    m_currentPacketSeq++;
    if (m_currentPacketSeq < m_testCount) {
        RelayServer currentServer;
        for (const auto &srv : m_relayServers) {
            if (srv.id == serverId) {
                currentServer = srv;
                break;
            }
        }
        if (!currentServer.id.isEmpty()) {
            QTimer::singleShot(m_testInterval, this, [this, currentServer]() {
                sendTestPacket(currentServer, m_currentPacketSeq);
            });
        }
    } else {
        completeServerTest(serverId);
    }
}

void War3Nat::completeServerTest(const QString &serverId)
{
    RelayTestResult result;
    result.serverId = serverId;
    result.testTime = QDateTime::currentDateTime();
    const QVector<qint64> &samples = m_latencySamples[serverId];
    if (samples.isEmpty()) {
        result.reachable = false;
        result.latency = 0;
        result.jitter = 0;
        result.packetLoss = 100;
        result.score = 0;
    } else {
        result.reachable = true;
        double sum = 0;
        for (qint64 sample : samples) {
            sum += sample;
        }
        result.latency = sum / samples.size();
        double variance = 0;
        for (qint64 sample : samples) {
            variance += (sample - result.latency) * (sample - result.latency);
        }
        result.jitter = qSqrt(variance / samples.size());
        result.packetLoss = ((m_testCount - samples.size()) * 100.0) / m_testCount;
        result.score = calculateScore(result);
    }
    m_testResults[serverId] = result;
    LOG_INFO(QString("服务器测试完成 - %1: 延迟=%2ms, 抖动=%3ms, 丢包=%4%, 评分=%5")
                 .arg(serverId).arg(result.latency, 0, 'f', 1)
                 .arg(result.jitter, 0, 'f', 1).arg(result.packetLoss, 0, 'f', 1)
                 .arg(result.score));
    emit relayTestCompleted(result);
    onNextTest();
}

void War3Nat::onNextTest()
{
    m_currentTestIndex++;
    if (m_currentTestIndex < m_relayServers.size()) {
        QTimer::singleShot(100, this, [this]() {
            performRelayTest(m_relayServers[m_currentTestIndex]);
        });
    } else {
        m_testInProgress = false;
        LOG_INFO("✅ 所有中继服务器测试完成");
        RelayServer optimalRelay = selectOptimalRelay();
        if (!optimalRelay.id.isEmpty()) {
            LOG_INFO(QString("🎯 选择最优中继服务器: %1 (评分: %2)")
                         .arg(optimalRelay.name).arg(optimalRelay.score));
            emit optimalRelaySelected(optimalRelay);
        }
        emit relaySelectionFinished();
    }
}

void War3Nat::onTestTimeout()
{
    if (m_currentTestIndex >= 0 && m_currentTestIndex < m_relayServers.size()) {
        const RelayServer &currentServer = m_relayServers[m_currentTestIndex];
        LOG_WARNING(QString("测试超时: %1").arg(currentServer.name));
        completeServerTest(currentServer.id);
    }
}

RelayServer War3Nat::selectOptimalRelay()
{
    if (m_testResults.isEmpty()) {
        return RelayServer();
    }
    RelayServer bestServer;
    int bestScore = -1;
    for (const RelayServer &server : m_relayServers) {
        if (!server.enabled) continue;
        if (m_testResults.contains(server.id)) {
            const RelayTestResult &result = m_testResults[server.id];
            if (result.reachable && result.score > bestScore) {
                bestScore = result.score;
                bestServer = server;
                bestServer.score = result.score;
                bestServer.latency = result.latency;
                bestServer.jitter = result.jitter;
                bestServer.packetLoss = result.packetLoss;
            }
        }
    }
    return bestServer;
}

int War3Nat::calculateScore(const RelayTestResult &result)
{
    if (!result.reachable) return 0;
    double latencyScore = qMax(0.0, 100.0 - (result.latency / 10.0));
    double jitterScore = qMax(0.0, 100.0 - (result.jitter * 2.0));
    double packetLossScore = 100.0 - result.packetLoss;
    double totalScore = (latencyScore * m_latencyWeight) +
                        (jitterScore * m_jitterWeight) +
                        (packetLossScore * m_packetLossWeight);
    return qMin(100, static_cast<int>(totalScore));
}

QByteArray War3Nat::createTestPacket(int sequence, const QByteArray &serverId)
{
    QByteArray packet;
    QDataStream stream(&packet, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::BigEndian);
    stream << quint32(0x524C5954);
    stream << quint16(sequence);
    stream << quint16(serverId.size());
    stream.writeRawData(serverId.constData(), serverId.size());
    stream << QDateTime::currentMSecsSinceEpoch();
    return packet;
}

bool War3Nat::parseTestResponse(const QByteArray &data, int &sequence, QByteArray &serverId)
{
    if (data.size() < 12) return false;
    QDataStream stream(data);
    stream.setByteOrder(QDataStream::BigEndian);
    quint32 magic;
    stream >> magic;
    if (magic != 0x524C5954) return false;
    quint16 seq;
    stream >> seq;
    sequence = seq;
    quint16 idSize;
    stream >> idSize;
    if (data.size() < 12 + idSize) return false;
    serverId.resize(idSize);
    stream.readRawData(serverId.data(), idSize);
    return true;
}

QHostAddress War3Nat::allocateRelayAddress()
{
    return m_relayAddress;
}

quint16 War3Nat::allocateRelayPort(bool evenPort)
{
    quint16 startPort = evenPort ? (m_minRelayPort % 2 == 0 ? m_minRelayPort : m_minRelayPort + 1) : m_minRelayPort;
    for (quint16 port = startPort; port <= m_maxRelayPort; port += (evenPort ? 2 : 1)) {
        if (!m_usedRelayPorts.contains(port)) {
            QUdpSocket testSocket;
            if (testSocket.bind(m_relayAddress, port, QUdpSocket::ShareAddress)) {
                testSocket.close();
                return port;
            }
        }
    }
    return 0;
}

void War3Nat::onAllocationExpiryCheck()
{
    QDateTime now = QDateTime::currentDateTime();
    QList<QString> expiredAllocations;
    for (auto it = m_allocations.begin(); it != m_allocations.end(); ++it) {
        if (now > it.value()->expiryTime) {
            expiredAllocations.append(it.key());
        }
    }
    for (const QString &allocationId : expiredAllocations) {
        QSharedPointer<Allocation> allocation = m_allocations.take(allocationId);
        m_relayMapping.remove(qMakePair(allocation->relayAddr.toString(), allocation->relayPort));
        m_usedRelayPorts.remove(allocation->relayPort);
        LOG_INFO(QString("🧹 清理过期分配: %1 (中继: %2:%3)")
                     .arg(allocationId, allocation->relayAddr.toString()).arg(allocation->relayPort));
        emit allocationExpired(allocationId);
    }
    if (!expiredAllocations.isEmpty()) {
        LOG_INFO(QString("📊 当前活跃分配: %1 个").arg(m_allocations.size()));
    }
}

NATType War3Nat::detectNATType(const QVector<RelayServer> &stunServers)
{
    if (stunServers.size() < 2) {
        LOG_WARNING("NAT检测需要至少两个STUN服务器");
        return NAT_UNKNOWN;
    }
    QUdpSocket socket;
    if (!socket.bind(QHostAddress(QHostAddress::AnyIPv4), 0)) {
        LOG_ERROR("无法绑定本地UDP套接字");
        return NAT_UNKNOWN;
    }
    QByteArray response;
    QHostAddress mappedAddr1, mappedAddr2, mappedAddr3;
    quint16 mappedPort1, mappedPort2, mappedPort3;
    // Test I: 标准绑定到服务器1
    if (!sendSTUNBindingRequest(&socket, stunServers[0].address, stunServers[0].port, response, mappedAddr1, mappedPort1, false, false)) {
        return NAT_BLOCKED;
    }
    // Test II: 请求改变端口 (同一服务器)
    if (!sendSTUNBindingRequest(&socket, stunServers[0].address, stunServers[0].port, response, mappedAddr2, mappedPort2, false, true)) {
        return NAT_SYMMETRIC_UDP_FIREWALL;
    }
    if (mappedAddr1 != mappedAddr2 || mappedPort1 != mappedPort2) {
        return NAT_SYMMETRIC;
    }
    // Test III: 请求改变IP和端口 (第二个服务器)
    if (!sendSTUNBindingRequest(&socket, stunServers[1].address, stunServers[1].port, response, mappedAddr3, mappedPort3, true, true)) {
        return NAT_PORT_RESTRICTED_CONE;
    }
    if (mappedAddr1 == socket.localAddress() && mappedPort1 == socket.localPort()) {
        return NAT_OPEN_INTERNET;
    }
    if (mappedAddr1 == mappedAddr3 && mappedPort1 == mappedPort3) {
        return NAT_FULL_CONE;
    }
    return NAT_RESTRICTED_CONE;
}

bool War3Nat::sendSTUNBindingRequest(QUdpSocket *socket, const QHostAddress &serverAddr, quint16 serverPort, QByteArray &response, QHostAddress &mappedAddr, quint16 &mappedPort, bool changeIP, bool changePort)
{
    QByteArray request;
    QDataStream stream(&request, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::BigEndian);
    stream << quint16(0x0001); // Binding Request
    stream << quint16(0); // Placeholder for length
    stream << quint32(0x2112A442);
    QByteArray transactionId = generateTransactionId();
    stream.writeRawData(transactionId.constData(), 12);
    quint16 msgLen = 0;
    if (changeIP || changePort) {
        stream << quint16(0x0003); // CHANGE-REQUEST
        stream << quint16(4);
        quint32 changeValue = 0;
        if (changeIP) changeValue |= 0x4;
        if (changePort) changeValue |= 0x2;
        stream << changeValue;
        msgLen += 8;
    }
    // Update length
    stream.device()->seek(2);
    stream << msgLen;
    qint64 bytesSent = socket->writeDatagram(request, serverAddr, serverPort);
    if (bytesSent <= 0) {
        LOG_ERROR(QString("发送STUN请求失败: %1").arg(socket->errorString()));
        return false;
    }
    if (!socket->waitForReadyRead(m_testTimeout)) {
        LOG_WARNING("STUN响应超时");
        return false;
    }
    response.resize(socket->pendingDatagramSize());
    QHostAddress senderAddr;
    quint16 senderPort;
    socket->readDatagram(response.data(), response.size(), &senderAddr, &senderPort);
    if (response.size() < 20) return false;
    int pos = 20;
    while (pos + 4 <= response.size()) {
        quint16 attrType = (static_cast<quint8>(response[pos]) << 8) | static_cast<quint8>(response[pos+1]);
        quint16 attrLen = (static_cast<quint8>(response[pos+2]) << 8) | static_cast<quint8>(response[pos+3]);
        if (attrType == STUN_ATTR_XOR_MAPPED_ADDRESS && attrLen >= 8) {
            quint8 family = static_cast<quint8>(response[pos+5]);
            if (family != 0x01) return false; // 只支持IPv4
            quint16 xoredPort = (static_cast<quint8>(response[pos+6]) << 8) | static_cast<quint8>(response[pos+7]);
            mappedPort = xoredPort ^ (0x2112A442 >> 16);
            quint32 xoredIP = (static_cast<quint8>(response[pos+8]) << 24) |
                              (static_cast<quint8>(response[pos+9]) << 16) |
                              (static_cast<quint8>(response[pos+10]) << 8) |
                              static_cast<quint8>(response[pos+11]);
            mappedAddr = QHostAddress(xoredIP ^ 0x2112A442);
            return true;
        }
        pos += 4 + attrLen;
        if (attrLen % 4 != 0) pos += 4 - (attrLen % 4);
    }
    return false;
}

QByteArray War3Nat::generateTransactionId()
{
    QByteArray id(12, 0);
    QRandomGenerator *gen = QRandomGenerator::global();
    gen->fillRange(reinterpret_cast<quint32*>(id.data()), 3);
    return id;
}

QByteArray War3Nat::generateNonce()
{
    return generateTransactionId().toHex();
}

void War3Nat::logRequest(const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId)
{
    QString shortTransactionId = QString(transactionId.toHex().left(16)) + "...";
    LOG_INFO(QString("✅ STUN/TURN请求 - 客户端: %1:%2 - 事务ID: %3")
                 .arg(clientAddr.toString())
                 .arg(clientPort)
                 .arg(shortTransactionId));
    RequestInfo info;
    info.clientAddr = clientAddr;
    info.clientPort = clientPort;
    info.timestamp = QDateTime::currentMSecsSinceEpoch();
    m_recentRequests[transactionId] = info;
}

void War3Nat::logResponse(const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId)
{
    QString shortTransactionId = QString(transactionId.toHex().left(16)) + "...";
    LOG_DEBUG(QString("📤 STUN/TURN响应 - 客户端: %1:%2 - 事务ID: %3")
                  .arg(clientAddr.toString())
                  .arg(clientPort)
                  .arg(shortTransactionId));
}

void War3Nat::logTURNAction(const QString &action, const QHostAddress &clientAddr, quint16 clientPort, const QString &details)
{
    QString message = QString("🔄 TURN %1 - 客户端: %2:%3").arg(action, clientAddr.toString()).arg(clientPort);
    if (!details.isEmpty()) {
        message += " - " + details;
    }
    LOG_INFO(message);
}

void War3Nat::onCleanupTimeout()
{
    qint64 currentTime = QDateTime::currentMSecsSinceEpoch();
    const qint64 FIVE_MINUTES = 5 * 60 * 1000;
    QList<QByteArray> toRemove;
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
        LOG_DEBUG(QString("🧹 清理了 %1 个过期请求记录").arg(removedCount));
    }
    static int cleanupCount = 0;
    cleanupCount++;
    if (cleanupCount >= 10) {
        LOG_INFO(QString("📊 服务器统计 - 总请求: %1, 总响应: %2, 活跃分配: %3")
                     .arg(m_totalRequests)
                     .arg(m_totalResponses)
                     .arg(m_allocations.size()));
        cleanupCount = 0;
    }
}
