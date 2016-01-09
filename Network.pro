#-------------------------------------------------
#
# Project created by QtCreator 2015-12-15T18:38:16
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Network
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    PcapUtils.cpp \
    algorithmonethread.cpp \
    algorithmtwothread.cpp

HEADERS  += mainwindow.h \
    NetworkHeader.h \
    PcapUtils.h \
    type.h \
    algorithmonethread.h \
    algorithmtwothread.h

FORMS    += mainwindow.ui

RESOURCES += \
    img.qrc
