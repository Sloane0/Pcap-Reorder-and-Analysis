#ifndef ALGORITHMONETHREAD_H
#define ALGORITHMONETHREAD_H

#include <QThread>
#include <QString>
#include "PcapUtils.h"

class AlgorithmOneThread : public QThread
{
    Q_OBJECT
public:
    AlgorithmOneThread();
    AlgorithmOneThread(QString sourceFile ,QString destFolder);
    void setSourceFile(QString src);
    void setDesFolder(QString des);

public slots:
    void changeValue(double);

signals:
    void valueChanged(double);

protected:
    void run();

private:
    QString sourceFile, destFolder;
    PcapUtils *pcapUtils;
};

#endif // ALGORITHMONETHREAD_H
