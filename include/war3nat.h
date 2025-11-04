#ifndef WAR3NAT_H
#define WAR3NAT_H

#include <QTimer>
#include <QDebug>
#include <QUdpSocket>
#include <QHostAddress>
#include <QCoreApplication>
#include <QCommandLineParser>

struct RequestInfo {
    QHostAddress clientAddr;
    quint16 clientPort;
    qint64 timestamp;
};

class War3Nat : public QObject
{
    Q_OBJECT

public:
    explicit War3Nat(QObject *parent = nullptr);
    ~War3Nat();

    // 设置强制端口重用
    void setForcePortReuse(bool force) { m_forcePortReuse = force; }

    // 服务器控制
    bool startServer(quint16 port = 3478);
    void stopServer();

    // 状态查询
    bool isRunning() const { return m_isRunning; }
    quint16 getPort() const { return m_serverPort; }

private slots:
    void onReadyRead();
    void handleSTUNRequest(const QByteArray &data, const QHostAddress &clientAddr, quint16 clientPort);
    void onCleanupTimeout();

private:
    QByteArray buildSTUNResponse(const QByteArray &request, const QHostAddress &clientAddr, quint16 clientPort);
    void logRequest(const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId);
    void logResponse(const QHostAddress &clientAddr, quint16 clientPort, const QByteArray &transactionId);

private:
    QUdpSocket *m_udpSocket;
    quint16 m_serverPort;
    bool m_isRunning;
    bool m_forcePortReuse;

    // 请求跟踪（用于统计和调试）
    QMap<QByteArray, RequestInfo> m_recentRequests;
    QTimer *m_cleanupTimer;

    // 统计信息
    quint64 m_totalRequests;
    quint64 m_totalResponses;
};

#endif // WAR3NAT_H
