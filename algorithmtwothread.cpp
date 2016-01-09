#include "algorithmtwothread.h"

AlgorithmTwoThread::AlgorithmTwoThread()
{
    pcapUtils = PcapUtils::getInstance();
    connect(pcapUtils, SIGNAL(valueAlgoTwoChanged(double)), this, SLOT(changeValue(double)));
}

AlgorithmTwoThread::AlgorithmTwoThread(QString sourceFile ,QString destFile)
{
    this->sourceFile = sourceFile;
    this->destFile = destFile;
}

void AlgorithmTwoThread::run()
{
    pcapUtils->algorithmTwo(sourceFile, destFile);
}


void AlgorithmTwoThread::setDesFolder(QString des)
{
    this->destFile = des;
}

void AlgorithmTwoThread::setSourceFolder(QString src)
{
    this->sourceFile = src;
}

void AlgorithmTwoThread::changeValue(double val)
{
    emit valueChanged(val);
}
