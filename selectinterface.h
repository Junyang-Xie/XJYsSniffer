#ifndef SELECTINTERFACE_H
#define SELECTINTERFACE_H

#include <QDialog>
#include <QWidget>
#include <QObject>
#include <QTableView>
#include <QList>
#include <QDialogButtonBox>
#include <QMessageBox>
#include <cstring>
#include "ui_selectinterface.h"
#include "necessary.h"
#include "sniffer.h"
#include "tablemodel.h"
#include "setview.h"

class selectInterface : public QDialog{
    Q_OBJECT

public:
    explicit selectInterface(sniffer *psniffer, QWidget *parent = 0);
    ~selectInterface();
    void changeLabel();
    Ui::SelectInterface *ui;

    char *devName;

signals:
    void buttonClicked();

private slots:

    void on_buttonBox_clicked(QAbstractButton *button);

private:
    sniffer *s;
    tableModel *ifViewModel;
    void initComboBox();

};

#endif // SELECTINTERFACE_H
