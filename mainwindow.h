#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "necessary.h"
#include "sniffer.h"
#include "filter.h"
#include <QList>
#include <QStandardItem>
#include "selectinterface.h"
#include "sniffthread.h"
#include "tablemodel.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

public slots:
    void treeViewUpdate(QList<QStandardItem*>*);

private slots:
    void on_actionStop_toggled(bool arg1);
    void on_actionStart_toggled(bool arg1);
    void on_actionSelectInterface_triggered();
    void changeStatus();
    void changeState(int state);
    void askForClearData();
    void on_actiontoButtom_toggled(bool arg1);
    void viewToButtom();
    void filt(int rowNumber);
    void on_pushButton_clicked();
    void on_lineEdit_returnPressed();

private:
    Ui::MainWindow *ui;

    int Status;
    sniffer *cap;
    selectInterface *selectIfDialog;
    QLabel *statusLabel;
    sniffThread *sThread;
    tableModel *tableViewModel;
    QStandardItemModel *treeModel;
    bool toButtom;
    Filter fil;

};


#endif // MAINWINDOW_H
