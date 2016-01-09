#include "algorithmonethread.h"

AlgorithmOneThread::AlgorithmOneThread()
{
    pcapUtils = PcapUtils::getInstance();

    connect(pcapUtils, SIGNAL(valueAlgoOneChanged(double)), this, SLOT(changeValue(double)));
}

AlgorithmOneThread::AlgorithmOneThread(QString sourceFile ,QString destFolder)
{
    this->sourceFile = sourceFile;
    this->destFolder = destFolder;
}

void AlgorithmOneThread::run()
{
    pcapUtils->algorithmOne(sourceFile, destFolder);
}

void AlgorithmOneThread::setDesFolder(QString des)
{
    this->destFolder = des;
}

void AlgorithmOneThread::setSourceFile(QString src)
{
    this->sourceFile = src;
}

void AlgorithmOneThread::changeValue(double val)
{
    emit valueChanged(val);
}
