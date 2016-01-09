
#include "NetworkHeader.h"
#include "PcapUtils.h"
#include <stdlib.h>
#include <QDebug>
#include <QDir>

PcapFileHeader *pcapFileHeader = NULL;

PcapUtils* PcapUtils::instance = NULL;

PcapUtils * PcapUtils::getInstance()
{
    if (instance == NULL) {
        instance = new PcapUtils();
    }
    return instance;
}

PcapFileHeader* PcapUtils::getPcapFileheader(QFile *file, long offset)
{
	PcapFileHeader *pcapFileHeader = new PcapFileHeader();
    memset(pcapFileHeader, 0, sizeof(PcapFileHeader));
    if (!file->seek(offset))
		return NULL;
    file->read((char *)pcapFileHeader, sizeof(PcapFileHeader));

	return pcapFileHeader;
}

PcapPackageHeader* PcapUtils::getPcapPackageHeader(QFile *file, long offset)
{
	PcapPackageHeader *pcapPackageHeader = new PcapPackageHeader();
	memset(pcapPackageHeader, 0, sizeof(PcapPackageHeader));
    if (!file->seek(offset))
		return NULL;
    file->read((char *)pcapPackageHeader, sizeof(PcapPackageHeader));

	return pcapPackageHeader;
}

IPHeader* PcapUtils::getIPHeader(QFile *file, long offset)
{
	IPHeader *ipHeader = new IPHeader();
	memset(ipHeader, 0, sizeof(IPHeader));
    if (!file->seek(offset))
        return NULL;
    file->read((char *)ipHeader, sizeof(IPHeader));

	return ipHeader;
}

TCPHeader* PcapUtils::getTCPHeader(QFile *file, long offset)
{
	TCPHeader *tcpHeader = new TCPHeader();
	memset(tcpHeader, 0, sizeof(TCPHeader));
    if (!file->seek(offset))
		return NULL;
    file->read((char *)tcpHeader, sizeof(TCPHeader));

	return tcpHeader;
}

UDPHeader* PcapUtils::getUDPHeader(QFile *file, long offset)
{
	UDPHeader *udpHeader = new UDPHeader();
	memset(udpHeader, 0, sizeof(UDPHeader));
    if (!file->seek(offset))
		return NULL;
    file->read((char *)udpHeader, sizeof(UDPHeader));
	return udpHeader;
}

SessionNode * PcapUtils::getSessionHeader(const QString fileName)
{
    SessionNode *tail, *sessionHeader = new SessionNode();
    sessionHeader->nextSession = NULL;
    sessionHeader->nextPackage = NULL;
    tail = sessionHeader;
    long offset = 0;
    int pcapPackageStartPosition = 0;

    QFile *file = new QFile(fileName);
    if (!file->open(QIODevice::ReadOnly))
        return NULL;

    long fileSize = file->size();

    pcapFileHeader = getPcapFileheader(file, 0);
    offset = 24;

    while (file->seek(offset)) {
        pcapPackageStartPosition = offset;
        PcapPackageHeader *pcapPackageHeader = getPcapPackageHeader(file, offset);
        if (pcapPackageHeader->capLength == 0)
            break;

        offset += sizeof(PcapPackageHeader) + 14;		//14 bytes is the size of MAC header
        IPHeader *ipHeader = getIPHeader(file, offset);

        offset += ((ipHeader->versionAndHeaderLength) & 0x0f) * 4;

        TCPHeader *tcpHeader = NULL;
        UDPHeader *udpHeader = NULL;

        PackageNode *searchNode = new PackageNode();
        memset(searchNode, 0, sizeof(PackageNode));
        searchNode->destinationAddress = ipHeader->destinationIP;
        searchNode->pcapTimeSeconds = pcapPackageHeader->timeSeconds;
        searchNode->pcapTimeUseconds = pcapPackageHeader->timeUSeconds;
        searchNode->sourceAddress = ipHeader->sourceIP;
        searchNode->pcapPackageStartPosition = pcapPackageStartPosition;
        searchNode->pcapPackageEndPosition = pcapPackageHeader->receiveLength
            + pcapPackageStartPosition - 1 + sizeof(PcapPackageHeader);

        if ((int)ipHeader->protocalType == 6) { //TCP
            tcpHeader = getTCPHeader(file, offset);
            searchNode->destinationPort = tcpHeader->destinationPort;
            searchNode->sourcePort = tcpHeader->sourcePort;
            searchNode->nodeType.tcpNode.tcpAcknowledgmentNO = tcpHeader->acknowledgmentNO;
            searchNode->nodeType.tcpNode.tcpSequenceNO = tcpHeader->sequenceNO;
            int tcpHeaderLength = ((tcpHeader->headerLengthAndReserved >> 4) & 0x0f) * 4;
            int tcpDataStartPostion = offset + tcpHeaderLength;
            searchNode->nodeType.tcpNode.tcpDataStartPosition = tcpDataStartPostion;
            searchNode->nodeType.tcpNode.tcpDataEndPosition = tcpDataStartPostion
                    + ntoh16(ipHeader->totalLength)
                    - ((ipHeader->versionAndHeaderLength) & 0x0f) * 4
                    - tcpHeaderLength;
            searchNode->protocalType = PROTOCAL_TYPE_TCP;
        }
        else if ((int)ipHeader->protocalType == 17) {	//UDP
            udpHeader = getUDPHeader(file, offset);
            searchNode->destinationPort = udpHeader->destinationPort;
            searchNode->sourcePort = udpHeader->sourcePort;
            searchNode->protocalType = PROTOCAL_TYPE_UDP;
        }

        if (searchNode->protocalType == PROTOCAL_TYPE_TCP || searchNode->protocalType == PROTOCAL_TYPE_UDP) {
            SessionNode *node = searchAmongSessions(sessionHeader, searchNode);
            if (node == NULL) {
                node = new SessionNode();
                memset(node, 0, sizeof(SessionNode));
                node->destinationAddress = searchNode->destinationAddress;
                node->destinationPort = searchNode->destinationPort;
                node->nextPackage = NULL;
                node->nextSession = NULL;
                node->protocalType = searchNode->protocalType;
                node->sourceAddress = searchNode->sourceAddress;
                node->sourcePort = searchNode->sourcePort;
                tail->nextSession = node;
                tail = tail->nextSession;
            }
            PackageNode *p = searchAmongPackages(node->nextPackage, searchNode);
            if (p == NULL) {
                p = node->nextPackage = new PackageNode();
                memset(p, 0, sizeof(PackageNode));
                p->next = searchNode;
            }
            else {
                searchNode->next = p->next;
                p->next = searchNode;
            }
        }
        offset = searchNode->pcapPackageEndPosition + 1;
        emit valueAlgoOneChanged((double)(searchNode->pcapPackageEndPosition+1)/(double)fileSize);
    }
    file->close();
    emit valueAlgoOneChanged(1);

    return sessionHeader;
}

void PcapUtils::algorithmOne(const QString fileName, const QString destFolder)
{
    QDir dir(destFolder);
    if (!dir.exists()) {
        dir.mkpath(destFolder);
    }

    SessionNode *sessionHeader = getSessionHeader(fileName);
//    travial(sessionHeader);
    writeAllSessions(fileName, destFolder, sessionHeader);
}

void PcapUtils::algorithmTwo(const QString srcFolder, const QString desFolder)
{
    QDir srcDir(srcFolder);
    QDir desDir(desFolder);
    QStringList srcFileList;
    int fileNumber = 0;

    if (!desDir.exists()) {
        desDir.mkpath(desFolder);
    }

    if (srcDir.exists()) {
        srcFileList = srcDir.entryList();
        fileNumber = srcFileList.length();
        for (int i = 0; i < fileNumber; i++) {
            QString fileName = srcFileList.at(i);
            if (fileName.startsWith("TCP")) {
                SessionNode *sessionHeader = getSessionHeader(srcDir.absoluteFilePath(fileName));
                QString desName;
                desName.append(desFolder).append("/").append(fileName).append(".txt");
                getWorkLoad(srcDir.absoluteFilePath(fileName), desName,sessionHeader->nextSession->nextPackage);
            }
            emit valueAlgoTwoChanged((double)(i+1) / (double)(fileNumber));
        }
    }
}

int PcapUtils::getWorkLoad(QString srcFileName, QString desFileName, PackageNode *packageHeader)
{
    PackageNode *p = packageHeader->next;
    PackageNode *q = packageHeader;
    QFile *srcPcap = new QFile(srcFileName);
    QFile *destPcap = new QFile(desFileName);

    if (!srcPcap->open(QIODevice::ReadOnly) || !destPcap->open(QIODevice::WriteOnly)) {
        return -1;
    }

    while (p != NULL) {
//        if (p->next != NULL) {
//            for (PackageNode *r = p->next, *k = p; r != NULL; ) {
//                //去掉重复的包
//                if (p->nodeType.tcpNode.tcpSequenceNO == r->nodeType.tcpNode.tcpSequenceNO
//                        && p->nodeType.tcpNode.tcpAcknowledgmentNO == r->nodeType.tcpNode.tcpAcknowledgmentNO) {
//                    k->next = r->next;
//                    r->next = NULL;
//                    free(r);
//                    r = k->next;
//                } else {
//                    r = r->next;
//                    k = k->next;
//                }
//            }
//        }

        if (!srcPcap->seek(p->nodeType.tcpNode.tcpDataStartPosition))
            return -1;

        int pcapSize = p->nodeType.tcpNode.tcpDataEndPosition
                - p->nodeType.tcpNode.tcpDataStartPosition;

        if (pcapSize <= 0) {
            p = p->next;
            q = q->next;
            continue;
        }

//        if (q->destinationAddress == p->sourceAddress && packageHeader->next != p) {
//            char extra[2] = {0x0D, 0x0A};
//            destPcap->write(extra, 2);
//        }

        qint64 retVal = 0;
        char *buffer = new char[pcapSize];
        if ((retVal = srcPcap->read(buffer, pcapSize)) > 0) {
            destPcap->write(buffer, retVal);
            delete[] buffer;
            p = p->next;
            q = q->next;
        }
     }
    destPcap->close();
    srcPcap->close();

    return 0;
}

SessionNode* PcapUtils::searchAmongSessions(SessionNode *sessionHeader, PackageNode *searchNode)
{
    SessionNode *p = sessionHeader->nextSession;
    while (p != NULL) {
        if ((p->destinationAddress == searchNode->destinationAddress
            && p->destinationPort == searchNode->destinationPort
            && p->sourceAddress == searchNode->sourceAddress
            && p->sourcePort == searchNode->sourcePort)
            || (p->destinationAddress == searchNode->sourceAddress
                && p->destinationPort == searchNode->sourcePort
                && p->sourceAddress == searchNode->destinationAddress
                && p->sourcePort == searchNode->destinationPort))
        {
            return p;
        }
        p = p->nextSession;
    }

    return NULL;
}

void PcapUtils::writeAllSessions(const QString fileName, const QString destFolder, SessionNode *sessionHeader)
{
    SessionNode *p = sessionHeader->nextSession;
    QFile *logFile = new QFile(destFolder + "/log.txt");
    if (!logFile->open(QIODevice::WriteOnly))
        return;
    QTextStream out(logFile);

    while (p != NULL) {
        QString desFileName;
        QString logFileItem;
        QString srcIP = IPToQString(p->sourceAddress);
        QString desIP = IPToQString(p->destinationAddress);
        QString sourcePort;
        QString desPort;
        sourcePort.sprintf("%d", ntoh16(p->sourcePort));
        desPort.sprintf("%d", ntoh16(p->destinationPort));

        if ((p->sourceAddress & 0xff) < (p->destinationAddress & 0xff)) { //ip最高4位比较大小
            if (p->protocalType == PROTOCAL_TYPE_TCP) {
                desFileName.append(destFolder).append("/TCP[").append(srcIP).append("][")
                        .append(sourcePort).append("][").append(desIP).append("][").append(desPort).append("].pcap");
                logFileItem.append("TCP[").append(srcIP).append("][").append(sourcePort)
                        .append("][").append(desIP).append("][").append(desPort).append("].pcap\r");
            }
            else if (p->protocalType == PROTOCAL_TYPE_UDP) {
                desFileName.append(destFolder).append("/UDP[").append(srcIP).append("][")
                        .append(sourcePort).append("][").append(desIP).append("][").append(desPort).append("].pcap");
                logFileItem.append("UDP[").append(srcIP).append("][").append(sourcePort)
                        .append("][").append(desIP).append("][").append(desPort).append("].pcap\r");
            }
        }
        else {
            if (p->protocalType == PROTOCAL_TYPE_TCP) {
                desFileName.append(destFolder).append("/TCP[").append(desIP).append("][")
                        .append(desPort).append("][").append(srcIP).append("][").append(sourcePort).append("].pcap");
                logFileItem.append("TCP[").append(desIP).append("][").append(desPort)
                        .append("][").append(srcIP).append("][").append(sourcePort).append("].pcap\r");
            }
            else if (p->protocalType == PROTOCAL_TYPE_UDP) {
                desFileName.append(destFolder).append("/UDP[").append(desIP).append("][")
                        .append(desPort).append("][").append(srcIP).append("][").append(sourcePort).append("].pcap");
                logFileItem.append("UDP[").append(desIP).append("][").append(desPort)
                        .append("][").append(srcIP).append("][").append(sourcePort).append("].pcap\r");
            }
        }

        writeSession(p->nextPackage, fileName, desFileName);
        out << logFileItem << endl;
        p = p->nextSession;
    }
    logFile->close();
}

/**
 *判断两个数据包的发送方向是否一致
 * @brief twoPackagesHaveTheSameDirection
 * @param packge1
 * @param packge2
 * @return
 */
bool PcapUtils::twoPackagesHaveTheSameDirection(PackageNode *packge1, PackageNode *packge2)
{
    if (packge1->sourceAddress == packge2->sourceAddress) {
        return true;
    } else {
        return false;
    }
}

/**
 * 根据TCP的序列号和应答号找到相应的插入位置，或者根据pcap包截获的时间找到udp包应该插入的位置
 * @brief searchAmongPackages
 * @param packageHeader
 * @param searchNode
 * @return 返回插入位置的前驱
 */
PackageNode* PcapUtils::searchAmongPackages(PackageNode *packageHeader, PackageNode *searchNode)
{
    if (packageHeader == NULL)
        return NULL;

    PackageNode *p = packageHeader;

    if (searchNode->protocalType == PROTOCAL_TYPE_UDP) {
        while (p->next != NULL) {
            if ( (searchNode->pcapTimeSeconds <= p->next->pcapTimeSeconds)
                    && (searchNode->pcapTimeUseconds < p->next->pcapTimeUseconds) )
                return p;

            p = p->next;
        }
    }

    else if (searchNode->protocalType == PROTOCAL_TYPE_TCP) {
        while ( p->next != NULL ) {
            if (twoPackagesHaveTheSameDirection(p->next, searchNode))
            {
                if ( ntoh32(searchNode->nodeType.tcpNode.tcpSequenceNO)
                     < ntoh32(p->next->nodeType.tcpNode.tcpSequenceNO)) {
                    return p;
                }
            }
            else
            {
                if (ntoh32(searchNode->nodeType.tcpNode.tcpSequenceNO)
                        < ntoh32(p->next->nodeType.tcpNode.tcpAcknowledgmentNO)) {
                    return p;
                }
            }
            p = p->next;
        }
    }
    return p;
}

void PcapUtils::travial(SessionNode *sessionHeader)
{
    SessionNode *p = sessionHeader->nextSession;
    QString ip;
    QFile file("debug.txt");
    char buff[100];
    if (!file.open(QIODevice::WriteOnly))
        return;

    while (p != 0) {
        PackageNode *q = p->nextPackage->next;
        while (q != 0) {
            if (q->protocalType == PROTOCAL_TYPE_TCP) {
                ip = IPToQString(q->sourceAddress);
                qDebug() << "Source IP:" << ip << endl;
                memset(buff, 0, sizeof(buff));
                sprintf(buff, "Source IP: %s\r\n", ip.toStdString().data());
                file.write(buff, strlen(buff));
                qDebug() << "Source Port:" << ntoh16(q->sourcePort) << endl;
                memset(buff, 0, sizeof(buff));
                sprintf(buff, "Source Port: %d\r\n", ntoh16(q->sourcePort));
                file.write(buff, strlen(buff));
                ip = IPToQString(q->destinationAddress);
                qDebug() << "Destination IP:" << ip << endl;
                memset(buff, 0, sizeof(buff));
                sprintf(buff, "Destination IP: %s\r\n", ip.toStdString().data());
                file.write(buff, strlen(buff));
                qDebug() << "Destination Port:" << ntoh16(q->destinationPort) << endl;
                memset(buff, 0, sizeof(buff));
                sprintf(buff, "Destination Port: %d\r\n", ntoh16(q->destinationPort));
                file.write(buff, strlen(buff));
                qDebug() << "seq no:" << q->nodeType.tcpNode.tcpSequenceNO << endl;
                qDebug() << "ack no:" << q->nodeType.tcpNode.tcpAcknowledgmentNO << endl << endl;
                memset(buff, 0, sizeof(buff));
                sprintf(buff, "seq no: %d\r\n", ntoh32(q->nodeType.tcpNode.tcpSequenceNO));
                file.write(buff, strlen(buff));
                memset(buff, 0, sizeof(buff));
                sprintf(buff, "ack no: %d\r\n", ntoh32(q->nodeType.tcpNode.tcpAcknowledgmentNO));
                file.write(buff, strlen(buff));
                memset(buff, 0, sizeof(buff));
                sprintf(buff, "-------------------------------------------------\r\r\n\n");
                file.write(buff, strlen(buff));
            }
            q = q->next;
        }
        p = p->nextSession;
    }
    file.close();
}

uint32 PcapUtils::ntoh32(uint32 data)
{
    return ((data & 0xff) << 24) | ((data & 0xff00) << 8) | ((data & 0xff0000) >> 8) | ((data & 0xff000000) >> 24);
}

uint16 PcapUtils::ntoh16(uint16 data)
{
    return ((data & 0xff) << 8) | ((data & 0xff00) >> 8);
}

QString PcapUtils::IPToQString(uint32 ip)
{
    char ipString[16];
    sprintf(ipString,  "%d.%d.%d.%d", (ip & 0xff), ((ip >> 8) & 0xff), ((ip >> 16) & 0xff), ((ip >> 24) & 0xff));
    return QString(ipString);
}

int PcapUtils::writeSession(PackageNode *packageHead, const QString srcFileName, const QString destFileName)
{
    PackageNode *p = packageHead->next;
    QFile *srcPcap = new QFile(srcFileName);
    QFile *destPcap = new QFile(destFileName);

    if (!srcPcap->open(QIODevice::ReadOnly) || !destPcap->open(QIODevice::WriteOnly))
        return -1;

    destPcap->write((char *)pcapFileHeader, sizeof(PcapFileHeader));

    while (p != NULL) {
        if (!srcPcap->seek(p->pcapPackageStartPosition))
            return -1;

        int pcapSize = p->pcapPackageEndPosition - p->pcapPackageStartPosition + 1;
        qint64 retVal = 0;
        char *buffer = new char[pcapSize];
        if ((retVal = srcPcap->read(buffer, pcapSize)) > 0) {
            destPcap->write(buffer, retVal);
            p = p->next;
        }
        delete[] buffer;
    }
    destPcap->close();
    srcPcap->close();

    return 0;
}

