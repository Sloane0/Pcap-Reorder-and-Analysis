#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTimer>
#include "PcapUtils.h"
#include "type.h"
#include "NetworkHeader.h"
#include "algorithmonethread.h"
#include "algorithmtwothread.h"

namespace Ui {
    class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void algorithmOneSelectFile();
    void algorithmOneSelectFolder();
    void algorithmTwoSelectSrcFolder();
    void algorithmTwoSelectDesFolder();
    void executeAlgorithmOne();
    void executeAlgorithmTwo();
    void executeAlgorithmThree();
    void changeValue(double val);

private:
    Ui::MainWindow *ui;
    AlgorithmOneThread *algorithmOneThread;
    AlgorithmTwoThread *algorithmTwoThread;
    bool isExecuteAlgorithmOne;
    bool isExecuteAlgorithmTwo;
};

#endif // MAINWINDOW_H
