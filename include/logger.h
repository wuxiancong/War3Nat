#ifndef LOGGER_H
#define LOGGER_H

#include <QFile>
#include <QMutex>
#include <QObject>
#include <QDateTime>
#include <QTextStream>

class Logger : public QObject
{
    Q_OBJECT

public:
    enum LogLevel {
        LOG_DEBUG = 0,
        LOG_INFO = 1,
        LOG_WARNING = 2,
        LOG_ERROR = 3,
        LOG_CRITICAL = 4
    };

    static Logger *instance();
    static void destroyInstance();

    void setLogLevel(LogLevel level);
    void setLogFile(const QString &filename);
    void setMaxFileSize(qint64 maxSize);
    void setBackupCount(int count);
    void enableConsoleOutput(bool enable);

    void debug(const QString &message);
    void info(const QString &message);
    void warning(const QString &message);
    void error(const QString &message);
    void critical(const QString &message);

    QString logLevelToString() const {
        switch (m_logLevel) {
        case LOG_DEBUG: return "debug";
        case LOG_INFO: return "info";
        case LOG_WARNING: return "warning";
        case LOG_ERROR: return "error";
        case LOG_CRITICAL: return "critical";
        default: return "info";
        }
    }

    static LogLevel logLevelFromString(const QString &levelStr) {
        QString lower = levelStr.toLower();
        if (lower == "debug") return LOG_DEBUG;
        if (lower == "info") return LOG_INFO;
        if (lower == "warning") return LOG_WARNING;
        if (lower == "error") return LOG_ERROR;
        if (lower == "critical") return LOG_CRITICAL;
        return LOG_INFO; // 默认
    }

    void setLogLevelFromString(const QString &levelStr) {
        setLogLevel(logLevelFromString(levelStr));
    }

private:
    Logger(QObject *parent = nullptr);
    ~Logger();

    void log(LogLevel level, const QString &message);
    bool rotateLogFileIfNeeded();
    bool performLogRotation();
    void consoleOutput(const QString &message, bool isError = false);

private:
    static Logger *m_instance;
    QFile *m_logFile;
    QTextStream *m_stream;
    QMutex m_mutex;
    LogLevel m_logLevel;
    bool m_consoleOutput;
    QString m_logFileName;
    QString m_logFileBaseName;
    QString m_logFileDir;
    qint64 m_maxFileSize;
    int m_backupCount;
};

// 宏定义便于使用
#define LOG_DEBUG(message) Logger::instance()->debug(message)
#define LOG_INFO(message) Logger::instance()->info(message)
#define LOG_WARNING(message) Logger::instance()->warning(message)
#define LOG_ERROR(message) Logger::instance()->error(message)
#define LOG_CRITICAL(message) Logger::instance()->critical(message)

#endif // LOGGER_H
