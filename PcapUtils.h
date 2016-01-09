#pragma once

#include <iostream>
#include "NetworkHeader.h"
#include <QString>
#include <QFile>

using namespace std;

class PcapUtils : public QObject
{
    Q_OBJECT
private:
    PcapUtils(){}
    static PcapUtils *instance;

public:
    static PcapUtils* getInstance();
    void algorithmOne(const QString fileName, const QString destFolder);
    void algorithmTwo(const QString fileName, const QString destFolder);
    PcapFileHeader* getPcapFileheader(QFile *file, long offset);
    PcapPackageHeader* getPcapPackageHeader(QFile *file, long offset);
    TCPHeader* getTCPHeader(QFile *file, long offset);
    UDPHeader* getUDPHeader(QFile *file, long offset);
    IPHeader* getIPHeader(QFile *file, long offset);
    SessionNode* searchAmongSessions(SessionNode *sessionHeader, PackageNode *searchNode);
    PackageNode* searchAmongPackages(PackageNode *packageHeader, PackageNode *searchNode);
    void travial(SessionNode *sessionHeader);
    uint32 ntoh32(uint32 data);
    uint16 ntoh16(uint16 data);
    QString IPToQString(uint32 ip);
    int writeSession(PackageNode *packageHead, const QString srcFileName, const QString destFileName);
    void writeAllSessions(const QString fileName, const QString destFolder, SessionNode *sessionHeader);
    SessionNode * getSessionHeader(const QString fileName);
    int getWorkLoad(QString srcFileName, QString desFileName, PackageNode *packageHeader);
    bool twoPackagesHaveTheSameDirection(PackageNode *packge1, PackageNode *packge2);

signals:
    void valueAlgoOneChanged(double);
    void valueAlgoTwoChanged(double);
};
