TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

LIBS += -lpcap -lpthread

SOURCES += main.cpp \
    arpspoofer.cpp

HEADERS += \
    Header.h \
    arpspoofer.h
