#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QFileDialog>
#include <QDir>
#include <QDebug>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    isExecuteAlgorithmOne = false;
    isExecuteAlgorithmTwo = false;
    algorithmOneThread = new AlgorithmOneThread();
    algorithmTwoThread = new AlgorithmTwoThread();

    connect(ui->btnAlgorithmOneSelectFile, SIGNAL(clicked()), this, SLOT(algorithmOneSelectFile()));
    connect(ui->btnAlgorithmOneSelectFolder, SIGNAL(clicked()), this, SLOT(algorithmOneSelectFolder()));
    connect(ui->btnAlgorithmTwoSelectFile, SIGNAL(clicked()), this, SLOT(algorithmTwoSelectSrcFolder()));
    connect(ui->btnAlgorithmTwoSelectFolder, SIGNAL(clicked()), this, SLOT(algorithmTwoSelectDesFolder()));
    connect(ui->btnExecuteAlgorithmOne, SIGNAL(clicked()), this, SLOT(executeAlgorithmOne()));
    connect(ui->btnExecuteAlgorithmTwo, SIGNAL(clicked()), this, SLOT(executeAlgorithmTwo()));


}

MainWindow::~MainWindow()
{
    delete ui;
    delete algorithmOneThread;
    delete algorithmTwoThread;
}

void MainWindow::changeValue(double val)
{
    if (algorithmOneThread->isRunning() || algorithmTwoThread->isRunning()) {
        ui->progressBar->setValue((int)(val * 1000));
    }
    if (val == 1.0) {
        ui->progressBar->setValue(1000);
        disconnect(algorithmOneThread, SIGNAL(valueChanged(double)), this, SLOT(changeValue(double)));
        if (isExecuteAlgorithmOne) {
            isExecuteAlgorithmOne = false;
            ui->btnExecuteAlgorithmOne->setEnabled(true);
            ui->btnAlgorithmOneSelectFile->setEnabled(true);
            ui->btnAlgorithmOneSelectFolder->setEnabled(true);

        }
        if (isExecuteAlgorithmTwo) {
            disconnect(algorithmTwoThread, SIGNAL(valueChanged(double)), this, SLOT(changeValue(double)));
            isExecuteAlgorithmTwo = false;
            ui->btnExecuteAlgorithmTwo->setEnabled(true);
            ui->btnAlgorithmTwoSelectFile->setEnabled(true);
            ui->btnAlgorithmTwoSelectFolder->setEnabled(true);
        }
    }
}

void MainWindow::algorithmOneSelectFile()
{
    QString file = QFileDialog::getOpenFileName(this, tr("选择源文件"), ".", tr("Pcap Files(*.pcap)"));
    if (file != NULL) {
        ui->labelAlgorithmOneSelectFile->setText(file);
    }
}

void MainWindow::algorithmOneSelectFolder()
{
    QString folder = QFileDialog::getExistingDirectory(this, tr("选择目标文件夹"), ".", QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (folder != NULL) {
        ui->labelAlgorithmOneSelectFolder->setText(folder);
    }
}

void MainWindow::algorithmTwoSelectSrcFolder()
{
    QString folder = QFileDialog::getExistingDirectory(this, tr("选择源文件夹"), ".", QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (folder != NULL) {
        ui->labelAlgorithmTwoSelectFile->setText(folder);
    }
}

void MainWindow::algorithmTwoSelectDesFolder()
{
    QString folder = QFileDialog::getExistingDirectory(this, tr("选择目标文件夹"), ".", QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (folder != NULL) {
        ui->labelAlgorithmTwoSelectFolder->setText(folder);
    }
}

void MainWindow::executeAlgorithmOne()
{
    QString sourceFile = ui->labelAlgorithmOneSelectFile->text();
    QString destFolder = ui->labelAlgorithmOneSelectFolder->text();

    connect(algorithmOneThread, SIGNAL(valueChanged(double)), this, SLOT(changeValue(double)));

    isExecuteAlgorithmOne = true;
    ui->progressBar->setValue(0);
    ui->btnExecuteAlgorithmOne->setEnabled(false);
    algorithmOneThread->setSourceFile(sourceFile);
    algorithmOneThread->setDesFolder(destFolder);
    ui->btnAlgorithmOneSelectFile->setEnabled(false);
    ui->btnAlgorithmOneSelectFolder->setEnabled(false);
    algorithmOneThread->start();
}

void MainWindow::executeAlgorithmTwo()
{
    QString srcFolder = ui->labelAlgorithmTwoSelectFile->text();
    QString desFolder = ui->labelAlgorithmTwoSelectFolder->text();

    connect(algorithmTwoThread, SIGNAL(valueChanged(double)), this, SLOT(changeValue(double)));

    isExecuteAlgorithmTwo = true;
    ui->progressBar->setValue(0);
    ui->btnExecuteAlgorithmTwo->setEnabled(false);
    ui->btnAlgorithmTwoSelectFile->setEnabled(false);
    ui->btnAlgorithmTwoSelectFolder->setEnabled(false);
    algorithmTwoThread->setSourceFolder(srcFolder);
    algorithmTwoThread->setDesFolder(desFolder);
    algorithmTwoThread->start();
}

void MainWindow::executeAlgorithmThree()
{

}

