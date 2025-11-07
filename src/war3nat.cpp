#include "logger.h"
#include "war3nat.h"

#include <QtMath>
#include <algorithm>
#include <QDateTime>
#include <QRunnable>
#include <QDataStream>
#include <QRandomGenerator>
#include <QNetworkInterface>

// ==================== PathTestTask实现 ====================

PathTestTask::PathTestTask(War3Nat *parent, const PathTestConfig &config)
    : m_parent(parent), m_config(config) {}

void PathTestTask::run() {
    m_parent->performPathTest(m_config);
}

// ==================== War3Nat实现 ====================

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
    , m_maxAllocations(1000)
    , m_realm("war3nat")
    , m_completedTests(0)
    , m_multiPathTestInProgress(false)
    , m_currentTestIndex(-1)
    , m_currentPacketSeq(0)
    , m_testInProgress(false)
    , m_minRelayPort(49152)
    , m_maxRelayPort(65535)
    , m_defaultLifetime(600)
    , m_testCount(5)
    , m_testTimeout(3000)
    , m_autoSelection(true)
    , m_testInterval(200)
    , m_latencyWeight(0.4)
    , m_jitterWeight(0.3)
    , m_packetLossWeight(0.2)
    , m_priorityWeight(0.1)
    , m_threadPool(new QThreadPool(this))
    , m_serverId("war3nat_server")
{
    // 连接信号槽
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

War3Nat::~War3Nat() {
    stopServer();
    if (m_threadPool) {
        m_threadPool->waitForDone(5000);
        delete m_threadPool;
    }
}

// ==================== 服务器管理 ====================

bool War3Nat::startServer(quint16 port) {
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

    // 启动日志
    LOG_INFO("🎉 War3Nat STUN/TURN 服务器启动成功");
    LOG_INFO(QString("📍 监听地址: %1:%2").arg(bindAddress.toString()).arg(m_serverPort));
    LOG_INFO(QString("🔄 中继地址: %1").arg(m_relayAddress.toString()));
    LOG_INFO("💡 服务类型: STUN服务器 (RFC 5389) + TURN中继 (RFC 5766)");
    LOG_INFO("🔧 支持功能: NAT类型检测、公网地址发现、数据中继、多中继选择、多路径测试");
    LOG_INFO(QString("🔒 端口重用: %1").arg(m_forcePortReuse ? "启用" : "禁用"));
    LOG_INFO(QString("🔄 中继端口范围: %1-%2").arg(m_minRelayPort).arg(m_maxRelayPort));

    return true;
}

void War3Nat::stopServer() {
    m_isRunning = false;

    // 停止所有定时器
    m_cleanupTimer->stop();
    m_allocationTimer->stop();
    m_testTimer->stop();
    m_selectionTimer->stop();

    // 停止测试
    stopMultiPathTest();
    stopRelaySelection();

    // 清理socket
    if (m_udpSocket) {
        m_udpSocket->close();
        delete m_udpSocket;
        m_udpSocket = nullptr;
    }

    // 清理数据
    m_recentRequests.clear();
    m_allocations.clear();
    m_relayMapping.clear();
    m_usedRelayPorts.clear();
    m_testResults.clear();
    m_latencySamples.clear();
    m_packetTimers.clear();
    m_pathTestResults.clear();

    LOG_INFO("🛑 War3Nat 服务器已停止");
    LOG_INFO(QString("📊 统计信息 - 总请求: %1, 总响应: %2").arg(m_totalRequests).arg(m_totalResponses));
}

// ==================== 网络数据接收 ====================

void War3Nat::onReadyRead() {
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
                          .arg(clientAddr.toString()).arg(clientPort).arg(bytesRead));

            // 使用线程池异步处理
            m_threadPool->start([this, datagram, clientAddr, clientPort]() {
                if (datagram.size() >= 20) {
                    quint16 messageType = (static_cast<quint8>(datagram[0]) << 8) | static_cast<quint8>(datagram[1]);
                    quint32 magicCookie = (static_cast<quint8>(datagram[4]) << 24) |
                                          (static_cast<quint8>(datagram[5]) << 16) |
                                          (static_cast<quint8>(datagram[6]) << 8) |
                                          static_cast<quint8>(datagram[7]);

                    if (magicCookie == 0x2112A442) {
                        // STUN/TURN协议消息
                        if (messageType == STUN_BINDING_REQUEST) {
                            handleSTUNRequest(datagram, clientAddr, clientPort);
                        } else if (messageType >= 0x0003 && messageType <= 0x0017) {
                            handleTURNRequest(datagram, clientAddr, clientPort);
                        } else {
                            LOG_WARNING(QString("未知的STUN/TURN消息类型: 0x%1")
                                            .arg(messageType, 4, 16, QLatin1Char('0')));
                        }
                    } else {
                        // 测试响应消息
                        if (!processTestResponse(datagram)) {
                            // 尝试处理路径测试响应
                            int sequence = 0;
                            QByteArray testId;
                            if (parsePathTestResponse(datagram, sequence, testId)) {
                                QString testIdStr = QString::fromUtf8(testId);
                                QByteArray expectedPacket = createPathTestPacket(sequence, testId);

                                if (m_packetTimers.contains(expectedPacket)) {
                                    qint64 latency = m_packetTimers[expectedPacket].elapsed();
                                    m_packetTimers.remove(expectedPacket);

                                    LOG_DEBUG(QString("收到路径测试响应 - 测试ID: %1, 序列: %2, 延迟: %3ms")
                                                  .arg(testIdStr).arg(sequence).arg(latency));
                                }
                            }
                        }
                    }
                }
            });
        }
    }
}

// ==================== 公共辅助方法 ====================

QSharedPointer<Allocation> War3Nat::findAllocation(const QHostAddress &clientAddr, quint16 clientPort) {
    for (auto it = m_allocations.begin(); it != m_allocations.end(); ++it) {
        if (it.value()->clientAddr == clientAddr && it.value()->clientPort == clientPort) {
            return it.value();
        }
    }
    return nullptr;
}

bool War3Nat::validateAllocation(const QHostAddress &clientAddr, quint16 clientPort,
                                 const QByteArray &transactionId, QByteArray &errorResponse) {
    auto allocation = findAllocation(clientAddr, clientPort);
    if (!allocation) {
        errorResponse = buildErrorResponse(transactionId, 437, "Allocation Mismatch");
        return false;
    }
    return true;
}

QVector<STUNAttribute> War3Nat::parseAttributes(const QByteArray &data, int startPos) {
    QVector<STUNAttribute> attributes;
    int pos = startPos;

    while (pos + 4 <= data.size()) {
        STUNAttribute attr;
        attr.type = (static_cast<quint8>(data[pos]) << 8) | static_cast<quint8>(data[pos+1]);
        attr.length = (static_cast<quint8>(data[pos+2]) << 8) | static_cast<quint8>(data[pos+3]);

        if (pos + 4 + attr.length > data.size()) break;

        attr.value = data.mid(pos + 4, attr.length);
        attributes.append(attr);

        pos += 4 + attr.length;
        if (attr.length % 4 != 0) {
            pos += 4 - (attr.length % 4);
        }
    }

    return attributes;
}

QHostAddress War3Nat::parseXorAddress(const QByteArray &data, int pos, quint16 &port) {
    if (pos + 8 > data.size()) return QHostAddress();

    quint16 xoredPort = (static_cast<quint8>(data[pos+6]) << 8) | static_cast<quint8>(data[pos+7]);
    port = xoredPort ^ (0x2112A442 >> 16);

    quint32 xoredIP = (static_cast<quint8>(data[pos+8]) << 24) |
                      (static_cast<quint8>(data[pos+9]) << 16) |
                      (static_cast<quint8>(data[pos+10]) << 8) |
                      static_cast<quint8>(data[pos+11]);

    return QHostAddress(xoredIP ^ 0x2112A442);
}

// ==================== STUN处理 ====================

void War3Nat::handleSTUNRequest(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort) {
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

    // 验证消息完整性
    if (data.size() < 20 + messageLength) {
        LOG_WARNING(QString("STUN消息长度不匹配: 声明长度=%1, 实际长度=%2")
                        .arg(messageLength).arg(data.size() - 20));
        return;
    }

    if (magicCookie != 0x2112A442) {
        LOG_WARNING(QString("无效的STUN Magic Cookie: 0x%1").arg(magicCookie, 8, 16, QLatin1Char('0')));
        return;
    }

    if (messageType == STUN_BINDING_REQUEST) {
        LOG_DEBUG(QString("处理STUN绑定请求 - 消息长度: %1 字节").arg(messageLength));
        logRequest(clientAddr, clientPort, transactionId);

        QByteArray response = buildSTUNResponse(data, clientAddr, clientPort);
        qint64 bytesSent = m_udpSocket->writeDatagram(response, clientAddr, clientPort);

        if (bytesSent > 0) {
            m_totalResponses++;
            logResponse(clientAddr, clientPort, transactionId);
            LOG_DEBUG(QString("📤 发送STUN响应到 %1:%2, 大小: %3 字节")
                          .arg(clientAddr.toString()).arg(clientPort).arg(bytesSent));
        } else {
            LOG_ERROR(QString("发送STUN响应失败: %1").arg(m_udpSocket->errorString()));
        }
    } else {
        LOG_WARNING(QString("未知的STUN消息类型: 0x%1, 长度: %2 字节")
                        .arg(messageType, 4, 16, QLatin1Char('0')).arg(messageLength));
    }
}

QByteArray War3Nat::buildSTUNResponse(const QByteArray &request, const QHostAddress &clientAddr, quint16 clientPort) {
    QByteArray transactionId = request.mid(8, 12);
    QByteArray response;
    QDataStream stream(&response, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::BigEndian);

    // STUN头部
    stream << quint16(0x0101);  // Binding Response
    stream << quint16(12);      // 消息长度
    stream << quint32(0x2112A442); // Magic Cookie
    stream.writeRawData(transactionId.constData(), 12); // Transaction ID

    // XOR-MAPPED-ADDRESS属性
    stream << quint16(0x0020);  // XOR-MAPPED-ADDRESS
    stream << quint16(8);       // 属性长度

    quint16 xoredPort = clientPort ^ (0x2112A442 >> 16);
    quint32 ipv4 = clientAddr.toIPv4Address();
    quint32 xoredIP = ipv4 ^ 0x2112A442;

    stream << quint8(0);        // 保留
    stream << quint8(0x01);     // IPv4家族
    stream << xoredPort;        // XORed端口
    stream << xoredIP;          // XORed IP地址

    // 日志记录映射关系
    QHostAddress mappedAddress(xoredIP ^ 0x2112A442);
    quint16 mappedPort = xoredPort ^ (0x2112A442 >> 16);

    LOG_DEBUG(QString("🔧 STUN映射 - 客户端: %1:%2 -> 公网: %3:%4")
                  .arg(clientAddr.toString()).arg(clientPort)
                  .arg(mappedAddress.toString()).arg(mappedPort));

    return response;
}

// ==================== TURN处理 ====================

void War3Nat::handleTURNRequest(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort) {
    if (data.size() < 20) {
        LOG_WARNING("TURN请求数据太小");
        return;
    }

    quint16 messageType = (static_cast<quint8>(data[0]) << 8) | static_cast<quint8>(data[1]);
    QByteArray transactionId = data.mid(8, 12);

    // 统一的认证检查（除了Allocate）
    if (messageType != TURN_ALLOCATE_REQUEST) {
        QString username;
        if (!authenticateRequest(data, transactionId, username, clientAddr, clientPort)) {
            QByteArray error = buildErrorResponse(transactionId, 401, "Unauthorized");
            m_udpSocket->writeDatagram(error, clientAddr, clientPort);
            return;
        }
    }

    logRequest(clientAddr, clientPort, transactionId);

    // 根据消息类型分发处理
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
    case TURN_DATA_INDICATION:
        handleDataIndication(data, clientAddr, clientPort);
        break;
    default:
        LOG_WARNING(QString("不支持的TURN消息类型: 0x%1").arg(messageType, 4, 16, QLatin1Char('0')));
        QByteArray error = buildErrorResponse(transactionId, 400, "Bad Request");
        m_udpSocket->writeDatagram(error, clientAddr, clientPort);
        break;
    }
}

// ==================== TURN请求处理实现 ====================

void War3Nat::handleAllocateRequest(const QByteArray &data, const QHostAddress &clientAddr,
                                    quint16 clientPort, const QByteArray &transactionId) {
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

    // 解析请求属性
    quint16 requestedTransport = 17; // UDP
    bool evenPortRequested = false;

    auto attributes = parseAttributes(data);
    for (const auto &attr : qAsConst(attributes)) {
        switch (attr.type) {
        case TURN_ATTR_REQUESTED_TRANSPORT:
            if (attr.length >= 4) {
                requestedTransport = static_cast<quint8>(attr.value[3]);
                LOG_DEBUG(QString("请求的传输协议: %1").arg(requestedTransport));
            }
            break;
        case TURN_ATTR_EVEN_PORT:
            if (attr.length >= 1) {
                evenPortRequested = (static_cast<quint8>(attr.value[0]) & 0x80) != 0;
                LOG_DEBUG(QString("偶数端口请求: %1").arg(evenPortRequested ? "是" : "否"));
            }
            break;
        case TURN_ATTR_DONT_FRAGMENT:
            LOG_DEBUG("不分片标志设置");
            break;
        default:
            break;
        }
    }

    // 验证传输协议
    if (requestedTransport != 17) {
        LOG_WARNING(QString("不支持的传输协议: %1，只支持UDP(17)").arg(requestedTransport));
        QByteArray errorResponse = buildErrorResponse(transactionId, 442, "Unsupported Transport Protocol");
        m_udpSocket->writeDatagram(errorResponse, clientAddr, clientPort);
        return;
    }

    // 生成分配ID
    QString allocationId = QString("%1_%2_%3")
                               .arg(clientAddr.toString())
                               .arg(clientPort)
                               .arg(QRandomGenerator::global()->generate());

    if (m_allocations.contains(allocationId)) {
        LOG_WARNING("客户端已存在分配，发送错误响应");
        QByteArray errorResponse = buildErrorResponse(transactionId, 437, "Allocation Mismatch");
        m_udpSocket->writeDatagram(errorResponse, clientAddr, clientPort);
        return;
    }

    // 分配中继资源
    QHostAddress relayAddr = allocateRelayAddress();
    quint16 relayPort = allocateRelayPort(evenPortRequested);

    if (relayPort == 0) {
        LOG_ERROR("无法分配中继端口，端口耗尽");
        QByteArray errorResponse = buildErrorResponse(transactionId, 508, "Insufficient Capacity");
        m_udpSocket->writeDatagram(errorResponse, clientAddr, clientPort);
        return;
    }

    // 创建分配记录
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

    // 发送响应
    QByteArray response = buildAllocateResponse(transactionId, relayAddr, relayPort, m_defaultLifetime);
    m_udpSocket->writeDatagram(response, clientAddr, clientPort);
    m_totalResponses++;

    logTURNAction("ALLOCATE", clientAddr, clientPort,
                  QString("分配ID: %1, 中继地址: %2:%3, 传输协议: UDP, 过期时间: %4")
                      .arg(allocationId, relayAddr.toString()).arg(relayPort)
                      .arg(alloc->expiryTime.toString("hh:mm:ss")));

    emit allocationCreated(allocationId, relayAddr, relayPort);
}

void War3Nat::handleRefreshRequest(const QByteArray &data, const QHostAddress &clientAddr,
                                   quint16 clientPort, const QByteArray &transactionId) {
    LOG_INFO(QString("🔄 TURN刷新请求来自 %1:%2").arg(clientAddr.toString()).arg(clientPort));

    quint32 requestedLifetime = 0;

    // 解析LIFETIME属性
    auto attributes = parseAttributes(data);
    for (const auto &attr : qAsConst(attributes)) {
        if (attr.type == TURN_ATTR_LIFETIME && attr.length >= 4) {
            requestedLifetime = (static_cast<quint8>(attr.value[0]) << 24) |
                                (static_cast<quint8>(attr.value[1]) << 16) |
                                (static_cast<quint8>(attr.value[2]) << 8) |
                                static_cast<quint8>(attr.value[3]);
            break;
        }
    }

    auto allocation = findAllocation(clientAddr, clientPort);
    if (!allocation) {
        LOG_WARNING("刷新请求：未找到分配记录");
        QByteArray errorResponse = buildErrorResponse(transactionId, 437, "Allocation Mismatch");
        m_udpSocket->writeDatagram(errorResponse, clientAddr, clientPort);
        return;
    }

    // 计算新的生命周期
    quint32 newLifetime = m_defaultLifetime;
    if (requestedLifetime > 0) {
        newLifetime = qMin(requestedLifetime, m_defaultLifetime);
    }

    // 更新分配信息
    allocation->expiryTime = QDateTime::currentDateTime().addSecs(newLifetime);
    allocation->lifetime = newLifetime;

    QByteArray response = buildRefreshResponse(transactionId, newLifetime);
    m_udpSocket->writeDatagram(response, clientAddr, clientPort);
    m_totalResponses++;

    logTURNAction("REFRESH", clientAddr, clientPort,
                  QString("分配ID: %1, 新生命周期: %2秒").arg(allocation->allocationId).arg(newLifetime));

    emit allocationRefreshed(allocation->allocationId, newLifetime);
}

void War3Nat::handleCreatePermission(const QByteArray &data, const QHostAddress &clientAddr,
                                     quint16 clientPort, const QByteArray &transactionId) {
    LOG_INFO(QString("🔄 TURN创建权限请求来自 %1:%2").arg(clientAddr.toString()).arg(clientPort));

    QHostAddress peerAddr;
    quint16 peerPort = 0;

    // 解析对等端地址
    auto attributes = parseAttributes(data);
    for (const auto &attr : qAsConst(attributes)) {
        if (attr.type == TURN_ATTR_XOR_PEER_ADDRESS && attr.length >= 8) {
            peerAddr = parseXorAddress(attr.value, 0, peerPort);
            break;
        }
    }

    if (peerAddr.isNull() || peerPort == 0) {
        LOG_WARNING("创建权限请求：无效的对等端地址");
        QByteArray errorResponse = buildErrorResponse(transactionId, 400, "Bad Request");
        m_udpSocket->writeDatagram(errorResponse, clientAddr, clientPort);
        return;
    }

    auto allocation = findAllocation(clientAddr, clientPort);
    if (!allocation) {
        LOG_WARNING("创建权限请求：未找到分配记录");
        QByteArray errorResponse = buildErrorResponse(transactionId, 437, "Allocation Mismatch");
        m_udpSocket->writeDatagram(errorResponse, clientAddr, clientPort);
        return;
    }

    // 添加权限
    allocation->permissions.insert(qMakePair(peerAddr.toString(), peerPort));

    QByteArray response = buildCreatePermissionResponse(transactionId);
    m_udpSocket->writeDatagram(response, clientAddr, clientPort);
    m_totalResponses++;

    logTURNAction("CREATE_PERMISSION", clientAddr, clientPort,
                  QString("分配ID: %1, 允许对等端: %2:%3")
                      .arg(allocation->allocationId, peerAddr.toString()).arg(peerPort));
}

void War3Nat::handleChannelBind(const QByteArray &data, const QHostAddress &clientAddr,
                                quint16 clientPort, const QByteArray &transactionId) {
    LOG_INFO(QString("🔄 TURN通道绑定请求来自 %1:%2").arg(clientAddr.toString()).arg(clientPort));

    quint16 channelNumber = 0;
    QHostAddress peerAddr;
    quint16 peerPort = 0;

    // 解析通道绑定属性
    auto attributes = parseAttributes(data);
    for (const auto &attr : qAsConst(attributes)) {
        if (attr.type == TURN_ATTR_CHANNEL_NUMBER && attr.length >= 4) {
            channelNumber = (static_cast<quint8>(attr.value[0]) << 8) | static_cast<quint8>(attr.value[1]);
        }
        else if (attr.type == TURN_ATTR_XOR_PEER_ADDRESS && attr.length >= 8) {
            peerAddr = parseXorAddress(attr.value, 0, peerPort);
        }
    }

    if (channelNumber == 0 || peerAddr.isNull() || peerPort == 0) {
        LOG_WARNING("通道绑定请求：无效的参数");
        QByteArray errorResponse = buildErrorResponse(transactionId, 400, "Bad Request");
        m_udpSocket->writeDatagram(errorResponse, clientAddr, clientPort);
        return;
    }

    auto allocation = findAllocation(clientAddr, clientPort);
    if (!allocation) {
        LOG_WARNING("通道绑定请求：未找到分配记录");
        QByteArray errorResponse = buildErrorResponse(transactionId, 437, "Allocation Mismatch");
        m_udpSocket->writeDatagram(errorResponse, clientAddr, clientPort);
        return;
    }

    // 建立通道绑定
    allocation->channelBindings[channelNumber] = qMakePair(peerAddr.toString(), peerPort);

    QByteArray response = buildChannelBindResponse(transactionId);
    m_udpSocket->writeDatagram(response, clientAddr, clientPort);
    m_totalResponses++;

    logTURNAction("CHANNEL_BIND", clientAddr, clientPort,
                  QString("分配ID: %1, 通道: %2, 对等端: %3:%4")
                      .arg(allocation->allocationId).arg(channelNumber)
                      .arg(peerAddr.toString()).arg(peerPort));
}

void War3Nat::handleSendIndication(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort) {
    auto allocation = findAllocation(clientAddr, clientPort);
    if (!allocation) {
        LOG_WARNING(QString("未找到分配记录: %1:%2").arg(clientAddr.toString()).arg(clientPort));
        return;
    }

    QHostAddress peerAddr;
    quint16 peerPort = 0;
    QByteArray relayData;

    // 解析发送指示
    auto attributes = parseAttributes(data);
    for (const auto &attr : qAsConst(attributes)) {
        if (attr.type == TURN_ATTR_XOR_PEER_ADDRESS && attr.length >= 8) {
            peerAddr = parseXorAddress(attr.value, 0, peerPort);
        } else if (attr.type == TURN_ATTR_DATA && attr.length > 0) {
            relayData = attr.value;
        }
    }

    if (peerAddr.isNull() || peerPort == 0 || relayData.isEmpty()) {
        LOG_WARNING("Send Indication: 无效的参数");
        return;
    }

    // 验证权限并中继数据
    if (validatePermission(*allocation, peerAddr, peerPort)) {
        relayDataToPeer(relayData, allocation->relayAddr, allocation->relayPort, peerAddr, peerPort);
        logTURNAction("SEND", clientAddr, clientPort,
                      QString("数据大小: %1 字节, 到 %2:%3")
                          .arg(relayData.size()).arg(peerAddr.toString()).arg(peerPort));
    } else {
        LOG_WARNING("Send Indication: 权限验证失败");
    }
}

void War3Nat::handleDataIndication(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort) {
    auto allocation = findAllocation(clientAddr, clientPort);
    if (!allocation) return;

    // 解析数据指示
    quint16 channelNumber = 0;
    QHostAddress peerAddr;
    quint16 peerPort = 0;
    QByteArray relayData;

    auto attributes = parseAttributes(data);
    for (const auto &attr : qAsConst(attributes)) {
        if (attr.type == TURN_ATTR_CHANNEL_NUMBER && attr.length >= 4) {
            channelNumber = (static_cast<quint8>(attr.value[0]) << 8) | static_cast<quint8>(attr.value[1]);
            // 从通道绑定查找对等端
            auto it = allocation->channelBindings.find(channelNumber);
            if (it != allocation->channelBindings.end()) {
                peerAddr = QHostAddress(it->first);
                peerPort = it->second;
            }
        } else if (attr.type == TURN_ATTR_XOR_PEER_ADDRESS && attr.length >= 8) {
            peerAddr = parseXorAddress(attr.value, 0, peerPort);
        } else if (attr.type == TURN_ATTR_DATA) {
            relayData = attr.value;
        }
    }

    // 中继数据
    if (!peerAddr.isNull() && peerPort > 0 && !relayData.isEmpty()) {
        relayDataToPeer(relayData, allocation->relayAddr, allocation->relayPort, peerAddr, peerPort);
    }
}

// ==================== 认证相关 ====================

bool War3Nat::authenticateRequest(const QByteArray &data, const QByteArray &transactionId,
                                  QString &username, const QHostAddress &clientAddr, quint16 clientPort) {
    Q_UNUSED(transactionId);
    Q_UNUSED(clientAddr);
    Q_UNUSED(clientPort);

    QString parsedUsername, realm, nonce;
    QByteArray integrity;

    // 解析认证属性
    auto attributes = parseAttributes(data);
    for (const auto &attr : qAsConst(attributes)) {
        if (attr.type == STUN_ATTR_USERNAME) {
            parsedUsername = QString::fromUtf8(attr.value);
        } else if (attr.type == STUN_ATTR_REALM) {
            realm = QString::fromUtf8(attr.value);
        } else if (attr.type == STUN_ATTR_NONCE) {
            nonce = QString::fromUtf8(attr.value);
        } else if (attr.type == STUN_ATTR_MESSAGE_INTEGRITY) {
            integrity = attr.value;
        }
    }

    // 基础验证
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
    QByteArray key = QCryptographicHash::hash((parsedUsername + ":" + m_realm + ":" + password).toUtf8(),
                                              QCryptographicHash::Md5);

    // 找到MESSAGE-INTEGRITY属性的位置
    int integrityPos = -1;
    for (int i = 0; i < attributes.size(); ++i) {
        if (attributes[i].type == STUN_ATTR_MESSAGE_INTEGRITY) {
            integrityPos = i;
            break;
        }
    }

    if (integrityPos == -1) return false;

    // 重新构建消息到MESSAGE-INTEGRITY属性前
    QByteArray message = data.left(20); // 头部
    for (int i = 0; i < integrityPos; ++i) {
        const auto &attr = attributes[i];
        message.append(reinterpret_cast<const char*>(&attr.type), 2);
        message.append(reinterpret_cast<const char*>(&attr.length), 2);
        message.append(attr.value);
        if (attr.length % 4 != 0) {
            message.append(QByteArray(4 - (attr.length % 4), 0));
        }
    }

    // 调整消息长度
    QDataStream lenStream(&message, QIODevice::ReadWrite);
    lenStream.setByteOrder(QDataStream::BigEndian);
    lenStream.device()->seek(2);
    quint16 adjustedLen = message.size() - 20;
    lenStream << adjustedLen;

    // 验证消息完整性
    QByteArray computed = hmacSha1(key, message);
    if (computed != integrity) {
        LOG_WARNING("认证失败: 消息完整性校验失败");
        return false;
    }

    username = parsedUsername;
    return true;
}

QByteArray War3Nat::hmacSha1(const QByteArray &key, const QByteArray &message) {
    int blockSize = 64; // SHA1 block size
    QByteArray normalizedKey = key;

    // 规范化密钥
    if (normalizedKey.length() > blockSize) {
        normalizedKey = QCryptographicHash::hash(normalizedKey, QCryptographicHash::Sha1);
    }
    normalizedKey.append(QByteArray(blockSize - normalizedKey.length(), 0));

    // 创建填充
    QByteArray innerPadding = QByteArray(blockSize, static_cast<char>(0x36));
    QByteArray outerPadding = QByteArray(blockSize, static_cast<char>(0x5C));

    // XOR操作
    for (int i = 0; i < blockSize; ++i) {
        innerPadding[i] = static_cast<char>(static_cast<unsigned char>(innerPadding[i]) ^
                                            static_cast<unsigned char>(normalizedKey[i]));
        outerPadding[i] = static_cast<char>(static_cast<unsigned char>(outerPadding[i]) ^
                                            static_cast<unsigned char>(normalizedKey[i]));
    }

    // 计算HMAC
    QByteArray innerHash = QCryptographicHash::hash(innerPadding + message, QCryptographicHash::Sha1);
    return QCryptographicHash::hash(outerPadding + innerHash, QCryptographicHash::Sha1);
}

// ==================== TURN响应构建 ====================

QByteArray War3Nat::buildAllocateResponse(const QByteArray &transactionId, const QHostAddress &relayAddr,
                                          quint16 relayPort, quint32 lifetime) {
    QByteArray response;
    QDataStream stream(&response, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::BigEndian);

    // 响应头部
    stream << quint16(0x0103);  // Allocate Response
    stream << quint16(32);      // 消息长度
    stream << quint32(0x2112A442);
    stream.writeRawData(transactionId.constData(), 12);

    // XOR-RELAYED-ADDRESS属性
    stream << quint16(TURN_ATTR_XOR_RELAYED_ADDRESS);
    stream << quint16(8);
    quint16 xoredPort = relayPort ^ (0x2112A442 >> 16);
    quint32 xoredIP = relayAddr.toIPv4Address() ^ 0x2112A442;
    stream << quint8(0);
    stream << quint8(0x01);
    stream << xoredPort;
    stream << xoredIP;

    // LIFETIME属性
    stream << quint16(TURN_ATTR_LIFETIME);
    stream << quint16(4);
    stream << lifetime;

    return response;
}

QByteArray War3Nat::buildRefreshResponse(const QByteArray &transactionId, quint32 lifetime) {
    QByteArray response;
    QDataStream stream(&response, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::BigEndian);

    stream << quint16(0x0104);  // Refresh Response
    stream << quint16(4);       // 消息长度
    stream << quint32(0x2112A442);
    stream.writeRawData(transactionId.constData(), 12);

    // LIFETIME属性
    stream << quint16(TURN_ATTR_LIFETIME);
    stream << quint16(4);
    stream << lifetime;

    return response;
}

QByteArray War3Nat::buildCreatePermissionResponse(const QByteArray &transactionId) {
    QByteArray response;
    QDataStream stream(&response, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::BigEndian);

    stream << quint16(0x0108);  // Create Permission Response
    stream << quint16(0);       // 消息长度
    stream << quint32(0x2112A442);
    stream.writeRawData(transactionId.constData(), 12);

    return response;
}

QByteArray War3Nat::buildChannelBindResponse(const QByteArray &transactionId) {
    QByteArray response;
    QDataStream stream(&response, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::BigEndian);

    stream << quint16(0x0109);  // Channel Bind Response
    stream << quint16(0);       // 消息长度
    stream << quint32(0x2112A442);
    stream.writeRawData(transactionId.constData(), 12);

    return response;
}

QByteArray War3Nat::buildErrorResponse(const QByteArray &transactionId, quint16 errorCode, const QString &reason) {
    QByteArray reasonBytes = reason.toUtf8();
    int reasonLen = reasonBytes.size();
    int padding = (4 - reasonLen % 4) % 4;
    int attrLen = 4 + reasonLen + padding;

    QByteArray response;
    QDataStream stream(&response, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::BigEndian);

    // 错误响应头部
    stream << quint16(0x0111);  // Error Response
    stream << quint16(attrLen);
    stream << quint32(0x2112A442);
    stream.writeRawData(transactionId.constData(), 12);

    // ERROR-CODE属性
    stream << quint16(STUN_ATTR_ERROR_CODE);
    stream << quint16(4 + reasonLen);
    stream << quint16(0);
    stream << quint8(errorCode / 100);
    stream << quint8(errorCode % 100);
    stream.writeRawData(reasonBytes.constData(), reasonLen);

    // 填充
    for (int i = 0; i < padding; ++i) {
        stream << quint8(0);
    }

    return response;
}

// ==================== 中继数据处理 ====================

bool War3Nat::validatePermission(const Allocation &allocation, const QHostAddress &peerAddr, quint16 peerPort) {
    return allocation.permissions.contains(qMakePair(peerAddr.toString(), peerPort));
}

void War3Nat::relayDataToPeer(const QByteArray &data, const QHostAddress &fromAddr, quint16 fromPort,
                              const QHostAddress &toAddr, quint16 toPort) {
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

// ==================== 中继服务器管理 ====================

void War3Nat::addRelayServer(const RelayServer &server) {
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

void War3Nat::removeRelayServer(const QString &serverId) {
    m_relayServers.erase(std::remove_if(m_relayServers.begin(), m_relayServers.end(),
                                        [&](const RelayServer& server) { return server.id == serverId; }),
                         m_relayServers.end());
}

void War3Nat::setRelayServers(const QVector<RelayServer> &servers) {
    m_relayServers = servers;
    LOG_INFO(QString("设置中继服务器列表: %1 个服务器").arg(servers.size()));
}

QVector<RelayServer> War3Nat::getRelayServers() const {
    return m_relayServers;
}

// ==================== 中继选择功能 ====================

void War3Nat::startRelaySelection() {
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

void War3Nat::stopRelaySelection() {
    if (m_testInProgress) {
        m_testInProgress = false;
        m_testTimer->stop();
        m_selectionTimer->stop();
        LOG_INFO("🛑 中继选择测试已停止");
    }
}

RelayServer War3Nat::getOptimalRelay() const {
    RelayServer optimal;
    int bestScore = -1;

    for (const RelayServer &server : qAsConst(m_relayServers)) {
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

QVector<RelayTestResult> War3Nat::getTestResults() const {
    QVector<RelayTestResult> results;
    results.reserve(m_testResults.size());

    for (auto it = m_testResults.constBegin(); it != m_testResults.constEnd(); ++it) {
        results.append(it.value());
    }

    return results;
}

void War3Nat::performRelayTest(const RelayServer &server) {
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

void War3Nat::sendTestPacket(const RelayServer &server, int seq) {
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

bool War3Nat::processTestResponse(const QByteArray &data) {
    int sequence;
    QByteArray serverIdBytes;

    if (!parseTestResponse(data, sequence, serverIdBytes)) {
        return false;
    }

    QString serverId = QString::fromUtf8(serverIdBytes);
    QByteArray expectedPacket = createTestPacket(sequence, serverIdBytes);

    if (!m_packetTimers.contains(expectedPacket)) {
        return false;
    }

    qint64 latency = m_packetTimers[expectedPacket].elapsed();
    m_packetTimers.remove(expectedPacket);
    m_latencySamples[serverId].append(latency);

    LOG_DEBUG(QString("收到测试响应 - 服务器: %1, 序列: %2, 延迟: %3ms")
                  .arg(serverId).arg(sequence).arg(latency));

    m_testTimer->stop();
    m_currentPacketSeq++;

    if (m_currentPacketSeq < m_testCount) {
        // 查找当前服务器并继续测试
        RelayServer currentServer;
        for (const auto &srv : qAsConst(m_relayServers)) {
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

    return true;
}

void War3Nat::completeServerTest(const QString &serverId) {
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

        // 计算平均延迟
        double sum = 0;
        for (qint64 sample : samples) {
            sum += sample;
        }
        result.latency = sum / samples.size();

        // 计算抖动
        double variance = 0;
        for (qint64 sample : samples) {
            variance += (sample - result.latency) * (sample - result.latency);
        }
        result.jitter = qSqrt(variance / samples.size());

        // 计算丢包率
        result.packetLoss = ((m_testCount - samples.size()) * 100.0) / m_testCount;

        // 计算评分
        result.score = calculateScore(result);
    }

    m_testResults[serverId] = result;

    LOG_INFO(QString("服务器测试完成 - %1: 延迟=%2ms, 抖动=%3ms, 丢包=%4%, 评分=%5")
                 .arg(serverId)
                 .arg(result.latency, 0, 'f', 1)
                 .arg(result.jitter, 0, 'f', 1)
                 .arg(result.packetLoss, 0, 'f', 1)
                 .arg(result.score));

    emit relayTestCompleted(result);
    onNextTest();
}

void War3Nat::onNextTest() {
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

void War3Nat::onTestTimeout() {
    if (m_currentTestIndex >= 0 && m_currentTestIndex < m_relayServers.size()) {
        const RelayServer &currentServer = m_relayServers[m_currentTestIndex];
        LOG_WARNING(QString("测试超时: %1").arg(currentServer.name));
        completeServerTest(currentServer.id);
    }
}

RelayServer War3Nat::selectOptimalRelay() {
    if (m_testResults.isEmpty()) {
        return RelayServer();
    }

    RelayServer bestServer;
    int bestScore = -1;

    for (const RelayServer &server : qAsConst(m_relayServers)) {
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

int War3Nat::calculateScore(const RelayTestResult &result) {
    if (!result.reachable) return 0;

    double latencyScore = qMax(0.0, 100.0 - (result.latency / 10.0));
    double jitterScore = qMax(0.0, 100.0 - (result.jitter * 2.0));
    double packetLossScore = 100.0 - result.packetLoss;

    double totalScore = (latencyScore * m_latencyWeight) +
                        (jitterScore * m_jitterWeight) +
                        (packetLossScore * m_packetLossWeight);

    return qMin(100, static_cast<int>(totalScore));
}

// ==================== 多路径测试功能 ====================

void War3Nat::startMultiPathTest(const QVector<PathTestConfig> &testConfigs) {
    if (testConfigs.isEmpty()) {
        LOG_WARNING("没有可用的路径测试配置");
        return;
    }

    if (m_multiPathTestInProgress) {
        LOG_WARNING("多路径测试正在进行中");
        return;
    }

    m_multiPathTestInProgress = true;
    m_testConfigs = testConfigs;
    m_pathTestResults.clear();
    m_completedTests = 0;

    LOG_INFO("🚀 开始多路径延迟测试");
    LOG_INFO(QString("测试路径数量: %1").arg(testConfigs.size()));

    emit multiPathTestStarted();

    // 使用线程池并行测试所有路径
    for (const auto &config : testConfigs) {
        PathTestTask *task = new PathTestTask(this, config);
        m_threadPool->start(task);
    }

    // 启动超时检查
    m_testTimer->start(testConfigs.size() * m_testTimeout * 2);
}

void War3Nat::stopMultiPathTest() {
    if (m_multiPathTestInProgress) {
        m_multiPathTestInProgress = false;
        m_testTimer->stop();
        LOG_INFO("🛑 多路径测试已停止");
    }
}

void War3Nat::performPathTest(const PathTestConfig &config) {
    if (!config.serverAddress.isNull() && config.serverPort > 0) {
        LOG_INFO(QString("开始路径测试: %1 (A:%2 -> 服务器:%3 <- B:%4)")
                     .arg(config.testId,
                          config.clientA.toString(),
                          config.serverAddress.toString(),
                          config.clientB.toString()));

        // 测试 A->服务器 的延迟
        QVector<qint64> aToServerLatencies = testOneWayLatency(
            config.clientA, config.serverAddress, config.serverPort, config.testCount);

        // 测试 B->服务器 的延迟
        QVector<qint64> bToServerLatencies = testOneWayLatency(
            config.clientB, config.serverAddress, config.serverPort, config.testCount);

        // 计算路径质量指标
        PathTestResult result;
        result.testId = config.testId;
        result.serverAddress = config.serverAddress;
        result.aToServerLatency = calculateAverageLatency(aToServerLatencies);
        result.bToServerLatency = calculateAverageLatency(bToServerLatencies);
        result.totalLatency = result.aToServerLatency + result.bToServerLatency;
        result.jitter = calculateJitter(aToServerLatencies, bToServerLatencies);
        result.packetLoss = calculatePacketLoss(aToServerLatencies, bToServerLatencies, config.testCount);
        result.score = calculatePathScore(result);
        result.reachable = (result.packetLoss < 100);
        result.testTime = QDateTime::currentDateTime();

        // 使用信号槽机制确保线程安全
        QMetaObject::invokeMethod(this, "onPathTestCompleted",
                                  Qt::QueuedConnection,
                                  Q_ARG(PathTestResult, result));
    }
}

QVector<qint64> War3Nat::testOneWayLatency(const QHostAddress &from,
                                           const QHostAddress &to,
                                           quint16 port,
                                           int count) {
    QVector<qint64> latencies;
    QUdpSocket socket;

    if (!socket.bind(from, 0, QUdpSocket::ShareAddress)) {
        LOG_ERROR(QString("无法绑定到地址: %1").arg(from.toString()));
        return latencies;
    }

    for (int i = 0; i < count; ++i) {
        QByteArray testPacket = createPathTestPacket(i, m_serverId.toUtf8());
        QElapsedTimer timer;
        timer.start();

        qint64 bytesSent = socket.writeDatagram(testPacket, to, port);
        if (bytesSent <= 0) {
            LOG_WARNING("发送测试包失败");
            continue;
        }

        // 等待响应
        if (socket.waitForReadyRead(m_testTimeout)) {
            QByteArray response;
            response.resize(socket.pendingDatagramSize());
            QHostAddress sender;
            quint16 senderPort;
            socket.readDatagram(response.data(), response.size(), &sender, &senderPort);

            if (parsePathTestResponse(response, i, m_serverId.toUtf8())) {
                latencies.append(timer.elapsed());
            }
        }
    }

    socket.close();
    return latencies;
}

void War3Nat::onPathTestCompleted(const PathTestResult &result) {
    m_pathTestResults[result.testId] = result;
    m_completedTests++;

    LOG_INFO(QString("路径测试完成: %1 - 总延迟: %2ms, 评分: %3")
                 .arg(result.testId).arg(result.totalLatency).arg(result.score));

    emit pathTestCompleted(result);

    // 检查是否所有测试都完成
    if (m_completedTests >= m_testConfigs.size()) {
        finishMultiPathTest();
    }
}

void War3Nat::finishMultiPathTest() {
    m_multiPathTestInProgress = false;
    m_testTimer->stop();

    // 选择最优路径
    PathTestResult bestPath = selectOptimalPath();

    LOG_INFO(QString("多路径测试完成，最优路径: %1 (总延迟: %2ms, 评分: %3)")
                 .arg(bestPath.testId).arg(bestPath.totalLatency).arg(bestPath.score));

    emit optimalPathSelected(bestPath);
    emit multiPathTestFinished();
}

PathTestResult War3Nat::selectOptimalPath() const {
    if (m_pathTestResults.isEmpty()) {
        return PathTestResult();
    }

    PathTestResult bestPath;
    int bestScore = -1;

    for (const auto &result : m_pathTestResults) {
        if (result.reachable && result.score > bestScore) {
            bestScore = result.score;
            bestPath = result;
        }
    }

    return bestPath;
}

PathTestResult War3Nat::getOptimalPath() const {
    return selectOptimalPath();
}

QVector<PathTestResult> War3Nat::getPathTestResults() const {
    QVector<PathTestResult> results;
    results.reserve(m_pathTestResults.size());

    for (auto it = m_pathTestResults.constBegin(); it != m_pathTestResults.constEnd(); ++it) {
        results.append(it.value());
    }

    return results;
}

int War3Nat::calculatePathScore(const PathTestResult &result) {
    if (!result.reachable) return 0;

    // 基于总延迟、抖动、丢包率计算评分
    double latencyScore = qMax(0.0, 100.0 - (result.totalLatency / 5.0));
    double jitterScore = qMax(0.0, 100.0 - (result.jitter * 5.0));
    double packetLossScore = 100.0 - result.packetLoss;

    double totalScore = (latencyScore * 0.5) +
                        (jitterScore * 0.3) +
                        (packetLossScore * 0.2);

    return qMin(100, static_cast<int>(totalScore));
}

double War3Nat::calculateAverageLatency(const QVector<qint64> &latencies) {
    if (latencies.isEmpty()) return 0;

    double sum = 0;
    for (qint64 latency : latencies) {
        sum += latency;
    }
    return sum / latencies.size();
}

double War3Nat::calculateJitter(const QVector<qint64> &latenciesA, const QVector<qint64> &latenciesB) {
    if (latenciesA.isEmpty() || latenciesB.isEmpty()) return 0;

    double avgA = calculateAverageLatency(latenciesA);
    double avgB = calculateAverageLatency(latenciesB);

    double varianceA = 0, varianceB = 0;
    for (qint64 latency : latenciesA) {
        varianceA += (latency - avgA) * (latency - avgA);
    }
    for (qint64 latency : latenciesB) {
        varianceB += (latency - avgB) * (latency - avgB);
    }

    double stdDevA = qSqrt(varianceA / latenciesA.size());
    double stdDevB = qSqrt(varianceB / latenciesB.size());

    return (stdDevA + stdDevB) / 2.0;
}

double War3Nat::calculatePacketLoss(const QVector<qint64> &latenciesA, const QVector<qint64> &latenciesB, int expectedCount) {
    int totalExpected = expectedCount * 2; // A和B各expectedCount个包
    int totalReceived = latenciesA.size() + latenciesB.size();

    if (totalExpected == 0) return 100;

    return ((totalExpected - totalReceived) * 100.0) / totalExpected;
}

// ==================== 工具方法 ====================

QByteArray War3Nat::createTestPacket(int sequence, const QByteArray &serverId) {
    QByteArray packet;
    QDataStream stream(&packet, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::BigEndian);

    stream << quint32(0x524C5954); // Magic: "RLYT"
    stream << quint16(sequence);
    stream << quint16(serverId.size());
    stream.writeRawData(serverId.constData(), serverId.size());
    stream << QDateTime::currentMSecsSinceEpoch();

    return packet;
}

QByteArray War3Nat::createPathTestPacket(int sequence, const QByteArray &testId) {
    QByteArray packet;
    QDataStream stream(&packet, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::BigEndian);

    stream << quint32(0x50415448); // Magic: "PATH"
    stream << quint16(sequence);
    stream << quint16(testId.size());
    stream.writeRawData(testId.constData(), testId.size());
    stream << QDateTime::currentMSecsSinceEpoch();

    return packet;
}

bool War3Nat::parseTestResponse(const QByteArray &data, int &sequence, QByteArray &serverId) {
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

bool War3Nat::parsePathTestResponse(const QByteArray &data, int expectedSequence, const QByteArray &expectedTestId) {
    if (data.size() < 12) return false;

    QDataStream stream(data);
    stream.setByteOrder(QDataStream::BigEndian);

    quint32 magic;
    stream >> magic;
    if (magic != 0x50415448) return false;

    quint16 sequence;
    stream >> sequence;
    if (sequence != expectedSequence) return false;

    quint16 idSize;
    stream >> idSize;
    if (data.size() < 12 + idSize) return false;

    QByteArray testId;
    testId.resize(idSize);
    stream.readRawData(testId.data(), idSize);

    return (testId == expectedTestId);
}

QHostAddress War3Nat::allocateRelayAddress() {
    return m_relayAddress;
}

quint16 War3Nat::allocateRelayPort(bool evenPort) {
    quint16 startPort = evenPort ?
                            (m_minRelayPort % 2 == 0 ? m_minRelayPort : m_minRelayPort + 1) :
                            m_minRelayPort;

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

void War3Nat::onAllocationExpiryCheck() {
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

// ==================== NAT类型检测 ====================

NATType War3Nat::detectNATType(const QVector<RelayServer> &stunServers) {
    if (stunServers.size() < 2) {
        LOG_WARNING("NAT检测需要至少两个STUN服务器");
        return NAT_UNKNOWN;
    }

    QUdpSocket socket;
    if (!socket.bind(QHostAddress(QHostAddress::AnyIPv4), 0)) {
        LOG_ERROR("无法绑定本地UDP套接字");
        return NAT_UNKNOWN;
    }

    LOG_INFO("🚀 开始完整NAT类型检测...");

    // 存储所有测试结果
    struct NATTestResult {
        QHostAddress mappedAddr;
        quint16 mappedPort;
        bool success;
        QString serverId;
    };

    QVector<NATTestResult> testResults;
    QSet<QString> uniqueIPs;
    QSet<quint16> uniquePorts;

    // ==================== 测试序列 ====================

    // Test 1: 基础绑定到服务器1
    NATTestResult test1;
    test1.success = sendSTUNBindingRequest(&socket, stunServers[0].address, stunServers[0].port,
                                           test1.mappedAddr, test1.mappedPort, false, false);
    test1.serverId = stunServers[0].id;
    testResults.append(test1);

    if (!test1.success) {
        LOG_WARNING("NAT检测测试1失败 - 可能被防火墙阻挡");
        return NAT_BLOCKED;
    }
    uniqueIPs.insert(test1.mappedAddr.toString());
    uniquePorts.insert(test1.mappedPort);

    // Test 2: 改变端口到服务器1
    NATTestResult test2;
    test2.success = sendSTUNBindingRequest(&socket, stunServers[0].address, stunServers[0].port,
                                           test2.mappedAddr, test2.mappedPort, false, true);
    test2.serverId = stunServers[0].id;
    testResults.append(test2);

    if (!test2.success) {
        LOG_DEBUG("NAT检测测试2失败 - 对称UDP防火墙");
        return NAT_SYMMETRIC_UDP_FIREWALL;
    }
    uniqueIPs.insert(test2.mappedAddr.toString());
    uniquePorts.insert(test2.mappedPort);

    // Test 3: 改变IP到服务器1
    NATTestResult test3;
    test3.success = sendSTUNBindingRequest(&socket, stunServers[0].address, stunServers[0].port,
                                           test3.mappedAddr, test3.mappedPort, true, false);
    test3.serverId = stunServers[0].id;
    testResults.append(test3);
    if (test3.success) {
        uniqueIPs.insert(test3.mappedAddr.toString());
        uniquePorts.insert(test3.mappedPort);
    }

    // Test 4: 基础绑定到服务器2
    NATTestResult test4;
    test4.success = sendSTUNBindingRequest(&socket, stunServers[1].address, stunServers[1].port,
                                           test4.mappedAddr, test4.mappedPort, false, false);
    test4.serverId = stunServers[1].id;
    testResults.append(test4);
    if (test4.success) {
        uniqueIPs.insert(test4.mappedAddr.toString());
        uniquePorts.insert(test4.mappedPort);
    }

    // Test 5: 改变IP+端口到服务器2
    NATTestResult test5;
    test5.success = sendSTUNBindingRequest(&socket, stunServers[1].address, stunServers[1].port,
                                           test5.mappedAddr, test5.mappedPort, true, true);
    test5.serverId = stunServers[1].id;
    testResults.append(test5);
    if (test5.success) {
        uniqueIPs.insert(test5.mappedAddr.toString());
        uniquePorts.insert(test5.mappedPort);
    }

    // ==================== 详细分析 ====================

    LOG_DEBUG(QString("📊 NAT检测统计: 成功测试=%1, 唯一IP=%2, 唯一端口=%3")
                  .arg(testResults.size())
                  .arg(uniqueIPs.size())
                  .arg(uniquePorts.size()));

    // 输出详细映射结果
    for (int i = 0; i < testResults.size(); ++i) {
        if (testResults[i].success) {
            LOG_DEBUG(QString("  测试%1: %2 -> %3:%4")
                          .arg(i + 1)
                          .arg(testResults[i].serverId)
                          .arg(testResults[i].mappedAddr.toString())
                          .arg(testResults[i].mappedPort));
        }
    }

    // ==================== 完整NAT类型判断 ====================

    // 1. 检查开放互联网
    QHostAddress localAddr = socket.localAddress();
    quint16 localPort = socket.localPort();
    if (!test1.mappedAddr.isNull() && !localAddr.isNull() &&
        test1.mappedAddr == localAddr && test1.mappedPort == localPort) {
        LOG_INFO("✅ 检测到开放互联网 (无NAT)");
        return NAT_OPEN_INTERNET;
    }

    // 2. 检查对称NAT - 任何变化都导致新映射
    if (test1.success && test2.success &&
        (test1.mappedAddr != test2.mappedAddr || test1.mappedPort != test2.mappedPort)) {
        LOG_INFO("🔄 检测到对称型NAT - 端口变更导致新映射");
        return NAT_SYMMETRIC;
    }

    // 3. 检查运营商级NAT (CGNAT) - 多个不同IP但端口一致
    if (uniqueIPs.size() > 2 && uniquePorts.size() == 1) {
        LOG_INFO("🏢 检测到运营商级NAT (CGNAT) - 多个出口IP共享端口");
        return NAT_CARRIER_GRADE;
    }

    // 4. 检查双重NAT - 多层映射特征
    if (test1.success && test4.success &&
        test1.mappedAddr != test4.mappedAddr &&
        uniquePorts.size() > 1) {
        LOG_INFO("🔗 检测到双重NAT - 多层映射");
        return NAT_DOUBLE_NAT;
    }

    // 5. 检查完全锥形NAT - 所有测试得到相同映射
    bool allSameMapping = true;
    for (int i = 1; i < testResults.size(); ++i) {
        if (testResults[i].success &&
            (testResults[i].mappedAddr != test1.mappedAddr ||
             testResults[i].mappedPort != test1.mappedPort)) {
            allSameMapping = false;
            break;
        }
    }
    if (allSameMapping) {
        LOG_INFO("🎯 检测到完全锥形NAT - 所有测试映射一致");
        return NAT_FULL_CONE;
    }

    // 6. 检查IP限制型NAT
    if (test3.success && test1.mappedAddr != test3.mappedAddr &&
        test1.mappedPort == test3.mappedPort) {
        LOG_INFO("🔒 检测到IP限制型NAT - IP变更影响映射");
        return NAT_IP_RESTRICTED;
    }

    // 7. 检查端口限制锥形NAT
    if (test5.success && test1.mappedAddr != test5.mappedAddr) {
        LOG_INFO("🚪 检测到端口限制锥形NAT - 服务器变更影响映射");
        return NAT_PORT_RESTRICTED_CONE;
    }

    // 8. 检查限制锥形NAT
    if (test4.success && test1.mappedAddr == test4.mappedAddr &&
        test1.mappedPort == test4.mappedPort) {
        LOG_INFO("🛡️ 检测到限制锥形NAT - 基础映射一致");
        return NAT_RESTRICTED_CONE;
    }

    // 9. 对称UDP防火墙
    if (!test2.success && test1.success) {
        LOG_INFO("🔥 检测到对称型UDP防火墙");
        return NAT_SYMMETRIC_UDP_FIREWALL;
    }

    LOG_WARNING("❓ 无法确定NAT类型，返回未知");
    return NAT_UNKNOWN;
}

bool War3Nat::sendSTUNBindingRequest(QUdpSocket *socket, const QHostAddress &serverAddr,
                                     quint16 serverPort, QHostAddress &mappedAddr,
                                     quint16 &mappedPort, bool changeIP, bool changePort) {
    QByteArray request;
    QDataStream stream(&request, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::BigEndian);

    // STUN消息头
    stream << quint16(0x0001); // Binding Request
    stream << quint16(0);      // 长度占位符
    stream << quint32(0x2112A442); // Magic Cookie

    QByteArray transactionId = generateTransactionId();
    stream.writeRawData(transactionId.constData(), 12);

    // 添加CHANGE-REQUEST属性（如果需要）
    quint16 msgLen = 0;
    if (changeIP || changePort) {
        stream << quint16(0x0003); // CHANGE-REQUEST类型
        stream << quint16(4);      // 属性长度
        quint32 changeValue = 0;
        if (changeIP) changeValue |= 0x4;
        if (changePort) changeValue |= 0x2;
        stream << changeValue;
        msgLen += 8;
    }

    // 更新消息长度
    stream.device()->seek(2);
    stream << msgLen;

    // 发送请求
    qint64 bytesSent = socket->writeDatagram(request, serverAddr, serverPort);
    if (bytesSent <= 0) {
        LOG_ERROR(QString("发送STUN请求失败: %1").arg(socket->errorString()));
        return false;
    }

    // 等待响应
    if (!socket->waitForReadyRead(5000)) { // 5秒超时
        LOG_WARNING(QString("STUN响应超时: %1:%2").arg(serverAddr.toString()).arg(serverPort));
        return false;
    }

    // 读取响应
    QByteArray response;
    response.resize(socket->pendingDatagramSize());
    QHostAddress senderAddr;
    quint16 senderPort;
    socket->readDatagram(response.data(), response.size(), &senderAddr, &senderPort);

    if (response.size() < 20) {
        LOG_WARNING("STUN响应数据太小");
        return false;
    }

    // 验证消息类型
    quint16 messageType = (static_cast<quint8>(response[0]) << 8) | static_cast<quint8>(response[1]);
    if (messageType != 0x0101) { // Binding Response
        LOG_WARNING("不是STUN绑定响应");
        return false;
    }

    // 解析XOR-MAPPED-ADDRESS属性
    auto attributes = parseAttributes(response);
    for (const auto &attr : attributes) {
        if (attr.type == STUN_ATTR_XOR_MAPPED_ADDRESS && attr.length >= 8) {
            quint8 family = static_cast<quint8>(attr.value[1]);
            if (family != 0x01) {
                LOG_WARNING("不支持非IPv4地址");
                return false; // 只支持IPv4
            }

            mappedAddr = parseXorAddress(attr.value, 0, mappedPort);
            return true;
        }
    }

    LOG_WARNING("未找到XOR-MAPPED-ADDRESS属性");
    return false;
}

QByteArray War3Nat::generateTransactionId() {
    QByteArray id(12, 0);
    QRandomGenerator *gen = QRandomGenerator::global();
    gen->fillRange(reinterpret_cast<quint32*>(id.data()), 3);
    return id;
}

QByteArray War3Nat::generateNonce() {
    return generateTransactionId().toHex();
}

// ==================== 日志方法 ====================

void War3Nat::logRequest(const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId) {
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

void War3Nat::logResponse(const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId) {
    QString shortTransactionId = QString(transactionId.toHex().left(16)) + "...";
    LOG_DEBUG(QString("📤 STUN/TURN响应 - 客户端: %1:%2 - 事务ID: %3")
                  .arg(clientAddr.toString())
                  .arg(clientPort)
                  .arg(shortTransactionId));
}

void War3Nat::logTURNAction(const QString &action, const QHostAddress &clientAddr, quint16 clientPort, const QString &details) {
    QString message = QString("🔄 TURN %1 - 客户端: %2:%3").arg(action, clientAddr.toString()).arg(clientPort);
    if (!details.isEmpty()) {
        message += " - " + details;
    }
    LOG_INFO(message);
}

void War3Nat::onCleanupTimeout() {
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
