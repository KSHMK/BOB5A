TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp \
    arpspoofer.cpp \
    filtering.cpp
LIBS += -lpcap
LIBS += -pthread

HEADERS += \
    arpspoofer.h \
    filtering.h \
    header.h
