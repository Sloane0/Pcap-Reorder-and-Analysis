#ifndef ALGORITHMTWOTHREAD_H
#define ALGORITHMTWOTHREAD_H

#include <QThread>
#include "PcapUtils.h"

class AlgorithmTwoThread : public QThread
{
    Q_OBJECT
public:
    AlgorithmTwoThread();
    AlgorithmTwoThread(QString sourceFile ,QString destFolder);
    void setSourceFolder(QString src);
    void setDesFolder(QString des);

public slots:
    void changeValue(double);

signals:
    void valueChanged(double);

protected:
    void run();

private:
    QString sourceFile, destFile;
    PcapUtils *pcapUtils;
};

#endif // ALGORITHMTWOTHREAD_H
