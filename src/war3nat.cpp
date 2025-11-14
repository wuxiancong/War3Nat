#include "logger.h"
#include "war3nat.h"

#include <QtMath>
#include <QDateTime>
#include <QRunnable>
#include <QDataStream>
#include <QRandomGenerator>
#include <QNetworkInterface>

War3Nat::War3Nat(QObject *parent)
    : QObject(parent)
    , m_isRunning(false)
    , m_serverPort(3478)
    , m_forcePortReuse(false)
    , m_udpSocket(nullptr)
    , m_totalRequests(0)
    , m_totalResponses(0)
    , m_cleanupTimer(new QTimer(this))
    , m_allocationTimer(new QTimer(this))
    , m_maxAllocations(1000)
    , m_realm("war3nat")
    , m_minRelayPort(49152)
    , m_maxRelayPort(65535)
    , m_defaultLifetime(600)
    , m_threadPool(new QThreadPool(this))
    , m_serverId("war3nat_server")
{
    // 连接信号槽
    connect(m_cleanupTimer, &QTimer::timeout, this, &War3Nat::onCleanupTimeout);
    connect(m_allocationTimer, &QTimer::timeout, this, &War3Nat::onAllocationExpiryCheck);

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

    LOG_INFO("🛑 War3Nat 服务器已停止");
    LOG_INFO(QString("📊 统计信息 - 总请求: %1, 总响应: %2").arg(m_totalRequests).arg(m_totalResponses));
}

// ==================== 网络数据接收 ====================

void War3Nat::onReadyRead()
{
    if (!m_udpSocket) {
        LOG_ERROR("onReadyRead called but m_udpSocket is null!");
        return;
    }

    while (m_udpSocket->hasPendingDatagrams()) {
        QByteArray datagram;
        qint64 pendingSize = m_udpSocket->pendingDatagramSize();
        if (pendingSize <= 0) continue;

        datagram.resize(pendingSize);

        QHostAddress clientAddr;
        quint16 clientPort;
        qint64 bytesRead = m_udpSocket->readDatagram(datagram.data(), datagram.size(), &clientAddr, &clientPort);

        if (bytesRead > 0) {
            m_totalRequests++;

            LOG_INFO("==========================================================");
            LOG_INFO(QString("📨 [RECV] 收到来自 %1:%2 的UDP包, 大小: %3 字节")
                         .arg(clientAddr.toString()).arg(clientPort).arg(bytesRead));
            LOG_INFO("[RAW DATA DUMP]:\n" + bytesToHex(datagram));

            // 检查是否是应用层文本消息
            QString message = QString::fromUtf8(datagram).trimmed();
            if (message.startsWith("TEST|")) {
                LOG_INFO("✅ [CLASSIFY] 识别为 [TEST] 消息. 开始处理...");
                processTestMessage(datagram, clientAddr, clientPort);
                LOG_INFO("==========================================================\n");
                continue;
            }
            if (message.startsWith("REGISTER_RELAY|")) {
                LOG_INFO("✅ [CLASSIFY] 识别为 [REGISTER_RELAY] 消息. 开始处理...");
                processRegisterRelayMessage(datagram, clientAddr, clientPort);
                LOG_INFO("==========================================================\n");
                continue;
            }

            // ==================== 修正后的二进制协议处理逻辑 ====================

            // 1. 首先检查是否是 "ROUT" 包 (Magic Cookie 在开头)
            if (datagram.size() >= 4) {
                quint32 routMagicCookie = (static_cast<quint8>(datagram[0]) << 24) |
                                          (static_cast<quint8>(datagram[1]) << 16) |
                                          (static_cast<quint8>(datagram[2]) << 8) |
                                          static_cast<quint8>(datagram[3]);

                if (routMagicCookie == 0x524F5554) { // "ROUT"
                    LOG_INFO("✅ [CLASSIFY] Magic Cookie (0x524F5554) 匹配! 识别为 [Path Test] 协议包.");
                    handlePathTestRequest(datagram, clientAddr, clientPort);
                    LOG_INFO("==========================================================\n");
                    continue; // 处理完毕
                }
            }

            // 2. 如果不是 "ROUT" 包，再检查是否是 STUN/TURN 包 (Magic Cookie 在第4字节)
            if (datagram.size() >= 20) {
                quint32 stunMagicCookie = (static_cast<quint8>(datagram[4]) << 24) |
                                          (static_cast<quint8>(datagram[5]) << 16) |
                                          (static_cast<quint8>(datagram[6]) << 8) |
                                          static_cast<quint8>(datagram[7]);

                if (stunMagicCookie == 0x2112A442) {
                    quint16 messageType = (static_cast<quint8>(datagram[0]) << 8) | static_cast<quint8>(datagram[1]);
                    LOG_INFO("✅ [CLASSIFY] Magic Cookie (0x2112A442) 匹配! 识别为 [STUN/TURN] 协议包.");

                    m_threadPool->start([this, datagram, clientAddr, clientPort, messageType]() {
                        if (messageType == STUN_BINDING_REQUEST) {
                            LOG_INFO("➡️ [DISPATCH] 分派到 handleSTUNRequest (Binding Request)");
                            handleSTUNRequest(datagram, clientAddr, clientPort);
                        } else if (messageType >= 0x0003 && messageType <= 0x0017) {
                            LOG_INFO("➡️ [DISPATCH] 分派到 handleTURNRequest (TURN Request)");
                            handleTURNRequest(datagram, clientAddr, clientPort);
                        } else {
                            LOG_WARNING(QString("⚠️ [DISPATCH] 未知STUN/TURN消息类型: 0x%1. 丢弃.")
                                            .arg(messageType, 4, 16, QChar('0')));
                        }
                    });
                    LOG_INFO("==========================================================\n");
                    continue; // 处理完毕
                }
            }

            // 3. 如果都不是，则为无法识别的包
            LOG_WARNING("❌ [CLASSIFY] 无法识别的二进制数据包. 两种Magic Cookie均不匹配.");
            LOG_INFO("==========================================================\n");
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
    QByteArray integrity;

    // 从请求中解析出 USERNAME 和 MESSAGE-INTEGRITY
    auto attributes = parseAttributes(data);
    for (const auto &attr : qAsConst(attributes)) {
        if (attr.type == STUN_ATTR_USERNAME) {
            username = QString::fromUtf8(attr.value);
        } else if (attr.type == STUN_ATTR_MESSAGE_INTEGRITY) {
            integrity = attr.value;
        }
    }

    // ==================== 新的认证流程 ====================
    // 如果第一次请求，连用户名都没有，直接返回401并附带 REALM 和 NONCE
    if (username.isEmpty() || integrity.isEmpty()) {
        LOG_WARNING("认证失败: 缺少用户名或完整性属性。发送401响应以启动二次握手。");
        QByteArray error = buildErrorResponse(transactionId, 401, "Unauthorized", true);
        m_udpSocket->writeDatagram(error, clientAddr, clientPort);
        return;
    }

    // 如果有认证信息，则进行验证
    if (!authenticateRequest(data, transactionId, username, clientAddr, clientPort)) {
        LOG_WARNING("认证失败: 消息完整性校验失败或用户无效。");
        QByteArray error = buildErrorResponse(transactionId, 401, "Unauthorized", true);
        m_udpSocket->writeDatagram(error, clientAddr, clientPort);
        return;
    }

    if (m_allocations.size() >= m_maxAllocations) {
        QByteArray error = buildErrorResponse(transactionId, 413, "Request Too Large", true);
        m_udpSocket->writeDatagram(error, clientAddr, clientPort);
        return;
    }

    LOG_INFO(QString("🔄 TURN分配请求来自 %1:%2").arg(clientAddr.toString()).arg(clientPort));

    // 解析请求属性
    quint16 requestedTransport = 17; // UDP
    bool evenPortRequested = false;

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
        QByteArray errorResponse = buildErrorResponse(transactionId, 437, "Allocation Mismatch", true);
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

void War3Nat::handlePathTestRequest(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort)
{
    // 增加对最小长度的检查，现在包含1字节的andRegister标志
    if (data.size() < 17) { // 4+2+2+8+1 = 17 (假设 testId 长度为0)
        LOG_WARNING(QString("❌ [Path Test] 数据包过短: %1 字节，期望至少 17 字节。").arg(data.size()));
        return;
    }

    QDataStream stream(data);
    stream.setByteOrder(QDataStream::BigEndian);

    quint32 magic;
    stream >> magic;
    if (magic != 0x524F5554) {
        LOG_WARNING("❌ [Path Test] Magic Cookie 不匹配 (已在 onReadyRead 检查过，此处为双重保险)。");
        return; // 理论上不会执行
    }

    quint16 seq;
    stream >> seq;

    quint16 idSize;
    stream >> idSize;

    // 再次验证数据包长度是否足够包含 testId 和后续字段
    if (data.size() < 12 + idSize + 1) { // 4+2+2(idSize) + idSize + 8(timestamp) + 1(flag)
        LOG_WARNING(QString("❌ [Path Test] 根据ID长度计算，数据包不完整。期望 > %1, 实际 %2")
                        .arg(12 + idSize).arg(data.size()));
        return;
    }

    QByteArray testIdBytes;
    testIdBytes.resize(idSize);
    stream.readRawData(testIdBytes.data(), idSize);

    quint64 timestamp;
    stream >> timestamp;

    quint8 registerFlag;
    stream >> registerFlag;
    bool andRegister = (registerFlag == 1);

    LOG_INFO(QString("✅ [Path Test] 解析到请求 - Test ID: %1, Seq: %2, 注册标志: %3")
                 .arg(QString::fromUtf8(testIdBytes)).arg(seq).arg(andRegister ? "true" : "false"));

    // ==================== 构建响应包 ====================
    // 我们不再简单地回传原始数据包，而是重新构建它。
    // 这更健壮，确保响应格式总是正确的，即使请求包末尾有额外数据。
    QByteArray response;
    QDataStream responseStream(&response, QIODevice::WriteOnly);
    responseStream.setByteOrder(QDataStream::BigEndian);

    responseStream << quint32(0x524F5554);                          // Magic
    responseStream << seq;                                          // Sequence
    responseStream << idSize;                                       // ID Length
    responseStream.writeRawData(testIdBytes.constData(), idSize);   // ID
    responseStream << timestamp;                                    // Timestamp
    responseStream << registerFlag;                                 // andRegister Flag
    // =========================================================

    qint64 bytesSent = m_udpSocket->writeDatagram(response, clientAddr, clientPort);
    if (bytesSent > 0) {
        LOG_INFO(QString("✅ [Path Test] 响应已发送给 %1:%2, 大小: %3 字节")
                     .arg(clientAddr.toString()).arg(clientPort).arg(bytesSent));
    } else {
        LOG_ERROR(QString("❌ [Path Test] 响应发送失败到 %1:%2").arg(clientAddr.toString()).arg(clientPort));
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

QByteArray War3Nat::buildErrorResponse(const QByteArray &transactionId, quint16 errorCode, const QString &reason, bool addAuthAttributes)
{
    QByteArray response;
    QDataStream stream(&response, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::BigEndian);

    // 头部
    stream << quint16(0x0111);      // Error Response
    stream << quint16(0);           // Placeholder for length
    stream << quint32(0x2112A442);  // Magic Cookie
    stream.writeRawData(transactionId.constData(), 12);

    // ERROR-CODE 属性
    QByteArray reasonBytes = reason.toUtf8();
    int reasonPadding = (4 - (reasonBytes.size() % 4)) % 4;
    stream << quint16(STUN_ATTR_ERROR_CODE);
    stream << quint16(4 + reasonBytes.size());
    stream << quint32( ( (errorCode / 100) << 8 ) | (errorCode % 100) );
    stream.writeRawData(reasonBytes.constData(), reasonBytes.size());
    if (reasonPadding > 0) stream.writeRawData(QByteArray(reasonPadding, '\0').constData(), reasonPadding);

    // ==================== 新增逻辑 ====================
    if (addAuthAttributes && errorCode == 401) {
        // REALM 属性
        QByteArray realmBytes = m_realm.toUtf8();
        int realmPadding = (4 - (realmBytes.size() % 4)) % 4;
        stream << quint16(STUN_ATTR_REALM);
        stream << quint16(realmBytes.size());
        stream.writeRawData(realmBytes.constData(), realmBytes.size());
        if (realmPadding > 0) stream.writeRawData(QByteArray(realmPadding, '\0').constData(), realmPadding);

        // NONCE 属性 (生成一个随机的nonce)
        QByteArray nonce = generateTransactionId(); // 复用这个函数生成随机字节
        int noncePadding = (4 - (nonce.size() % 4)) % 4;
        stream << quint16(STUN_ATTR_NONCE);
        stream << quint16(nonce.size());
        stream.writeRawData(nonce.constData(), nonce.size());
        if (noncePadding > 0) stream.writeRawData(QByteArray(noncePadding, '\0').constData(), noncePadding);
    }
    // ===============================================

    // 最终更新长度
    stream.device()->seek(2);
    stream << quint16(response.size() - 20);

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

void War3Nat::forwardToP2PServer(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort)
{
    // P2P服务器地址和端口 - 可以从配置读取或硬编码
    QHostAddress p2pServerAddr = QHostAddress("127.0.0.1"); // 本地P2P服务器
    quint16 p2pServerPort = 6112; // P2P服务器端口

    // 构建转发消息，包含原始客户端信息
    QByteArray forwardData = data;

    // 可选：在消息中添加转发标记，便于P2P服务器识别
    if (!data.startsWith("FORWARDED|")) {
        QString originalMessage = QString(data);
        forwardData = QString("FORWARDED|%1|%2|%3|%4")
                          .arg(clientAddr.toString())
                          .arg(clientPort)
                          .arg(QDateTime::currentMSecsSinceEpoch())
                          .arg(originalMessage)
                          .toUtf8();
    }

    qint64 bytesSent = m_udpSocket->writeDatagram(forwardData, p2pServerAddr, p2pServerPort);

    if (bytesSent > 0) {
        LOG_DEBUG(QString("✅ 应用消息转发成功: %1:%2 -> P2P服务器 (%3 字节)")
                      .arg(clientAddr.toString()).arg(clientPort).arg(bytesSent));
        m_totalResponses++;
    } else {
        LOG_ERROR(QString("❌ 应用消息转发失败: %1").arg(m_udpSocket->errorString()));
    }
}

void War3Nat::processRegisterRelayMessage(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort)
{
    QString message = QString(data);
    QStringList parts = message.split('|');

    if (parts.size() < 6) {
        LOG_WARNING(QString("❌ 无效的REGISTER_RELAY格式: %1").arg(message));
        return;
    }

    QString gameId = parts[1];
    QString relayIp = parts[2];
    QString relayPort = parts[3];
    QString natType = parts[4];
    QString status = parts[5];

    LOG_INFO(QString("🔄 处理中继注册: 客户端 %1:%2, 游戏ID: %3 中继 %4:%5, NAT: %6 状态: %7")
                 .arg(clientAddr.toString()).arg(clientPort)
                 .arg(gameId, relayIp, relayPort, natType, status));

    // 验证中继地址是否有效（是否由本服务器分配）
    bool isValidRelay = validateRelayAddress(relayIp, relayPort.toUShort(), clientAddr, clientPort);

    if (isValidRelay) {
        LOG_INFO("✅ 中继地址验证通过，转发到P2P服务器");

        // 直接转发到P2P服务器
        forwardToP2PServer(data, clientAddr, clientPort);

        // 可选：发送即时确认
        sendRelayRegistrationAck(clientAddr, clientPort, relayIp, relayPort);
    } else {
        LOG_WARNING("❌ 中继地址验证失败，可能不是由本服务器分配");

        // 发送错误响应
        QByteArray errorResponse = QString("REGISTER_RELAY_ERROR|INVALID_RELAY_ADDRESS|%1|%2")
                                       .arg(relayIp, relayPort)
                                       .toUtf8();
        m_udpSocket->writeDatagram(errorResponse, clientAddr, clientPort);
    }
}

bool War3Nat::validateRelayAddress(const QString &relayIp, quint16 relayPort, const QHostAddress &clientAddr, quint16 clientPort)
{
    // 检查中继IP是否匹配本服务器
    if (relayIp != m_relayAddress.toString() && relayIp != "127.0.0.1" && relayIp != "localhost") {
        LOG_WARNING(QString("中继IP不匹配: %1 != %2").arg(relayIp, m_relayAddress.toString()));
        return false;
    }

    // 检查中继端口是否在有效范围内
    if (relayPort < m_minRelayPort || relayPort > m_maxRelayPort) {
        LOG_WARNING(QString("中继端口超出范围: %1, 有效范围: %2-%3")
                        .arg(relayPort).arg(m_minRelayPort).arg(m_maxRelayPort));
        return false;
    }

    // 检查该端口是否已分配
    if (!m_usedRelayPorts.contains(relayPort)) {
        LOG_WARNING(QString("中继端口未分配: %1").arg(relayPort));
        return false;
    }

    // 可选：检查分配记录是否匹配
    for (auto it = m_allocations.begin(); it != m_allocations.end(); ++it) {
        const auto &allocation = it.value();
        if (allocation->relayPort == relayPort &&
            allocation->clientAddr == clientAddr &&
            allocation->clientPort == clientPort) {
            return true; // 找到匹配的分配记录
        }
    }

    LOG_WARNING("未找到匹配的分配记录");
    return false;
}

void War3Nat::sendRelayRegistrationAck(const QHostAddress &clientAddr, quint16 clientPort, const QString &relayIp, const QString &relayPort)
{
    QString transactionId = QString(generateTransactionId().toHex().left(8));

    QByteArray ackMessage = QString("REGISTER_RELAY_ACK|%1|%2|%3")
                                .arg(transactionId, relayIp, relayPort)
                                .toUtf8();

    qint64 bytesSent = m_udpSocket->writeDatagram(ackMessage, clientAddr, clientPort);

    if (bytesSent > 0) {
        LOG_DEBUG(QString("✅ 中继注册确认已发送: %1 字节").arg(bytesSent));
    } else {
        LOG_ERROR("❌ 中继注册确认发送失败");
    }
}

bool War3Nat::processTestMessage(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort)
{
    QString message = QString::fromUtf8(data).trimmed();

    // 定义测试消息模式
    QVector<QString> testPatterns = {
        "TEST|CONNECTIVITY"
    };

    bool isTestMessage = false;
    QString responseMessage;

    // 检查是否是测试消息
    for (const QString &pattern : qAsConst(testPatterns)) {
        if (message.contains(pattern, Qt::CaseInsensitive)) {
            isTestMessage = true;

            // 根据不同的测试消息生成不同的响应
            if (message.contains("CONNECTIVITY", Qt::CaseInsensitive)) {
                responseMessage = "TEST|CONNECTIVITY|OK|War3Nat_Server_v3.0";
            } else {
                responseMessage = "DEFAULT_RESPONSE|Message received at " +
                                  QDateTime::currentDateTime().toString("hh:mm:ss.zzz").toUtf8();
            }
            break;
        }
    }

    // 如果是测试消息，发送响应
    if (isTestMessage) {
        QByteArray response = responseMessage.toUtf8();
        qint64 bytesSent = m_udpSocket->writeDatagram(response, clientAddr, clientPort);

        if (bytesSent > 0) {
            LOG_DEBUG(QString("🔄 测试响应 - 客户端: %1:%2 - 消息: %3 - 响应: %4")
                          .arg(clientAddr.toString())
                          .arg(clientPort)
                          .arg(message, responseMessage));
            m_totalResponses++;
        } else {
            LOG_ERROR(QString("发送测试响应失败: %1").arg(m_udpSocket->errorString()));
        }

        return true;
    }

    return false;
}

// ==================== 工具方法 ====================

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

QByteArray War3Nat::generateTransactionId() {
    QByteArray id(12, 0);
    QRandomGenerator *gen = QRandomGenerator::global();
    gen->fillRange(reinterpret_cast<quint32*>(id.data()), 3);
    return id;
}

QString War3Nat::bytesToHex(const QByteArray &data, int bytesPerLine)
{
    QString hexString;
    for (int i = 0; i < data.size(); ++i) {
        if (i > 0 && i % bytesPerLine == 0) {
            hexString += "\n";
        }
        hexString += QString("%1 ").arg(static_cast<quint8>(data[i]), 2, 16, QChar('0')).toUpper();
    }
    return hexString;
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
