#include "logger.h"
#include <QDir>
#include <QDebug>
#include <iostream>

Logger *Logger::m_instance = nullptr;

Logger *Logger::instance()
{
    static QMutex mutex;
    if (!m_instance) {
        QMutexLocker locker(&mutex);
        if (!m_instance) {
            m_instance = new Logger();
        }
    }
    return m_instance;
}

void Logger::destroyInstance()
{
    if (m_instance) {
        delete m_instance;
        m_instance = nullptr;
    }
}

Logger::Logger(QObject *parent)
    : QObject(parent)
    , m_logFile(nullptr)
    , m_stream(nullptr)
    , m_logLevel(LOG_INFO)
    , m_consoleOutput(true)
    , m_maxFileSize(10 * 1024 * 1024) // 默认10MB
    , m_backupCount(5) // 默认5个备份
{
}

Logger::~Logger()
{
    if (m_stream) {
        m_stream->flush();
        delete m_stream;
        m_stream = nullptr;
    }
    if (m_logFile) {
        m_logFile->close();
        delete m_logFile;
        m_logFile = nullptr;
    }
}

void Logger::setMaxFileSize(qint64 maxSize)
{
    QMutexLocker locker(&m_mutex);
    m_maxFileSize = maxSize;
}

void Logger::setBackupCount(int count)
{
    QMutexLocker locker(&m_mutex);
    m_backupCount = count;
}

void Logger::setLogLevel(LogLevel level)
{
    QMutexLocker locker(&m_mutex);
    m_logLevel = level;
}

void Logger::setLogFile(const QString &filename)
{
    QMutexLocker locker(&m_mutex);

    if (m_stream) {
        m_stream->flush();
        delete m_stream;
        m_stream = nullptr;
    }
    if (m_logFile) {
        m_logFile->close();
        delete m_logFile;
        m_logFile = nullptr;
    }

    m_logFileName = filename;

    // 解析日志文件基础信息
    QFileInfo fileInfo(filename);
    m_logFileBaseName = fileInfo.completeBaseName(); // 不包含扩展名的文件名
    m_logFileDir = fileInfo.absolutePath();

    // 确保目录存在
    QDir dir = fileInfo.dir();
    if (!dir.exists()) {
        dir.mkpath(".");
    }

    m_logFile = new QFile(filename);
    if (m_logFile->open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        m_stream = new QTextStream(m_logFile);
        m_stream->setCodec("UTF-8");
    } else {
        std::cerr << "Cannot open log file: " << filename.toStdString() << std::endl;
        delete m_logFile;
        m_logFile = nullptr;
    }
}

void Logger::enableConsoleOutput(bool enable)
{
    QMutexLocker locker(&m_mutex);
    m_consoleOutput = enable;
}

bool Logger::rotateLogFileIfNeeded()
{
    if (m_logFileName.isEmpty() || !m_logFile) {
        return false;
    }

    // 检查当前文件大小
    if (m_logFile->size() < m_maxFileSize) {
        return false;
    }

    // 关闭当前的文件流
    if (m_stream) {
        m_stream->flush();
        delete m_stream;
        m_stream = nullptr;
    }
    if (m_logFile) {
        m_logFile->close();
        delete m_logFile;
        m_logFile = nullptr;
    }

    // 执行日志轮转
    return performLogRotation();
}

bool Logger::performLogRotation()
{
    QDir logDir(m_logFileDir);
    if (!logDir.exists()) {
        return false;
    }

    QString logExtension = ".log";

    // 删除最旧的备份文件
    QString oldestBackup = m_logFileBaseName + "_" + QString::number(m_backupCount) + logExtension;
    QFile::remove(logDir.filePath(oldestBackup));

    // 重命名现有的备份文件
    for (int i = m_backupCount - 1; i >= 1; i--) {
        QString oldName = m_logFileBaseName + "_" + QString::number(i) + logExtension;
        QString newName = m_logFileBaseName + "_" + QString::number(i + 1) + logExtension;

        QFile::rename(logDir.filePath(oldName), logDir.filePath(newName));
    }

    // 将当前日志文件重命名为第一个备份
    QString firstBackup = m_logFileBaseName + "_1" + logExtension;
    if (QFile::exists(m_logFileName)) {
        QFile::rename(m_logFileName, logDir.filePath(firstBackup));
    }

    // 重新打开日志文件
    m_logFile = new QFile(m_logFileName);
    if (m_logFile->open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        m_stream = new QTextStream(m_logFile);
        m_stream->setCodec("UTF-8");

        // 写入轮转提示信息
        QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss.zzz");
        QString rotateMessage = QString("[%1] [INFO] Log file rotated, new file started")
                                    .arg(timestamp);
        *m_stream << rotateMessage << "\n";
        m_stream->flush();

        // 注意：这里不能使用 LOG_INFO，因为可能造成递归调用
        std::cout << "Log file rotation completed successfully" << std::endl;
        return true;
    } else {
        std::cerr << "Failed to reopen log file after rotation: " << m_logFileName.toStdString() << std::endl;
        delete m_logFile;
        m_logFile = nullptr;
        return false;
    }
}

void Logger::debug(const QString &message)
{
    log(LOG_DEBUG, message);
}

void Logger::info(const QString &message)
{
    log(LOG_INFO, message);
}

void Logger::warning(const QString &message)
{
    log(LOG_WARNING, message);
}

void Logger::error(const QString &message)
{
    log(LOG_ERROR, message);
}

void Logger::critical(const QString &message)
{
    log(LOG_CRITICAL, message);
}

void Logger::log(LogLevel level, const QString &message)
{
    if (level < m_logLevel) return;

    QMutexLocker locker(&m_mutex);

    QString levelStr;
    switch (level) {
    case LOG_DEBUG: levelStr = "DEBUG"; break;
    case LOG_INFO: levelStr = "INFO"; break;
    case LOG_WARNING: levelStr = "WARNING"; break;
    case LOG_ERROR: levelStr = "ERROR"; break;
    case LOG_CRITICAL: levelStr = "CRITICAL"; break;
    }

    QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss.zzz");
    QString logMessage = QString("[%1] [%2] %3")
                             .arg(timestamp, levelStr, message);

    // 总是输出到控制台（用于调试）
    std::cout << logMessage.toStdString() << std::endl;
    std::cout.flush(); // 强制刷新

    // 输出到文件
    if (!m_stream && !m_logFileName.isEmpty()) {
        // 尝试重新打开文件
        m_logFile = new QFile(m_logFileName);
        if (m_logFile->open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
            m_stream = new QTextStream(m_logFile);
            m_stream->setCodec("UTF-8");
            std::cout << "重新打开日志文件成功: " << m_logFileName.toStdString() << std::endl;
        } else {
            std::cerr << "无法打开日志文件: " << m_logFileName.toStdString()
                << " 错误: " << m_logFile->errorString().toStdString() << std::endl;
            delete m_logFile;
            m_logFile = nullptr;
            return;
        }
    }

    if (m_stream) {
        *m_stream << logMessage << "\n";
        m_stream->flush(); // 强制刷新到磁盘
        m_logFile->flush(); // 双重保险
    }

    // 如果文件流仍然不可用，输出错误
    if (!m_stream) {
        std::cerr << "日志文件流不可用，消息丢失: " << logMessage.toStdString() << std::endl;
    }
}
