#include <pcap.h>
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "setview.h"
#include "sniffer.h"
#include "sniffthread.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    Status = STOP;
    cap = new sniffer;
    selectIfDialog = new selectInterface(cap,this);

    treeModel = new QStandardItemModel;
    ui->treeView->setModel(treeModel);
    ui->treeView->setHeaderHidden(true);
    ui->pushButton->setToolTip(QObject::tr("import query as Type=Data like dst=255.255.255.255\ntype can be src, dst, sport, dport, pro"));

    //View Setting
    QList<QString> tableHeaderName = {"NO.","Time","Source","Destination","Protacal","Length"};
    tableViewModel = new tableModel(&tableHeaderName);
    ui->tableView->setModel(tableViewModel->Model());
    QList<int> tableHeaderWidth = {50,100,120,120,50,50};
    defaultView *setV = new defaultView(ui->tableView,&tableHeaderWidth);


    /* For Test
    QList<QString> aItem = {"100","15.000152","192.168.0.204","192.168.0.204","ICMP","1523","12345678901234567890123456789012345"};
    QList<QStandardItem *> bItem = {new QStandardItem(QString("1")),new QStandardItem(QString("1")),new QStandardItem(QString("1")),new QStandardItem(QString("1")),new QStandardItem(QString("1")),new QStandardItem(QString("1")),new QStandardItem(QString("1"))};
    tableViewModel->addItemList(&aItem);
    tableViewModel->Model()->appendRow(bItem);
    std::cout<<"item(0,0)="<<(tableViewModel->Model())->item(0,0)->accessibleText().toStdString()<<std::endl;
    std::cout<<"column="<<(tableViewModel->Model())->columnCount()<<std::endl;
    std::cout<<"row="<<(tableViewModel->Model())->rowCount()<<std::endl;
    */

    QString *tmps = new QString("Now Interface is ");
    *tmps += QString(cap->nowDevice());
    statusLabel = new QLabel(*tmps,this);
    ui->statusBar->addPermanentWidget(statusLabel);

    sThread = new sniffThread(cap,tableViewModel);

    connect(selectIfDialog,&selectInterface::buttonClicked,this,&MainWindow::changeStatus);
    connect(sThread,&sniffThread::stateIsChanged,this,&MainWindow::changeState);
    connect(sThread,&sniffThread::newItem,this,&MainWindow::viewToButtom);
    connect(sThread,&sniffThread::newItem,this,&MainWindow::filt);

    connect(ui->tableView->selectionModel(),&QItemSelectionModel::selectionChanged,tableViewModel,&tableModel::selectRowChanged);
    connect(tableViewModel,&tableModel::treeViewUpgrade,this,&MainWindow::treeViewUpdate);
}

MainWindow::~MainWindow()
{
    delete ui;
    delete cap;
}

void MainWindow::changeState(int state){
    switch (state) {
    case 0:{
        on_actionStop_toggled(true);
        break;
    }
    case 1:{
        on_actionStart_toggled(true);
        break;
    }
    case 2:{
        on_actionStart_toggled(false);
        break;
    }
    default:
        break;
    }
}

void MainWindow::askForClearData(){
    if(tableViewModel->showIndex() > 0){
        if(QMessageBox::warning(this, tr("XJY's Sniffer"), tr("<p>Do you want to clear the data?</p>"), QMessageBox::Yes|QMessageBox::No ) == QMessageBox::Yes){
            tableViewModel->clearAll();
        }
        else{
        }
    }
}

void MainWindow::viewToButtom(){
    if(toButtom){
        ui->tableView->scrollToBottom();
    }
}

void MainWindow::on_actionStart_toggled(bool arg1)
{
    if(arg1){
        if(Status==STOP){
            treeModel->clear();
            sThread->start();
        }
        else sThread->setRunState(START);
        Status = START;
        ui->actionStop->setEnabled(true);
        ui->actionStop->setChecked(false);
        ui->actionSelectInterface->setEnabled(false);
    }
    else{
        ui->actionStart->setEnabled(true);
        ui->actionStart->setChecked(false);
        Status = PAUSE;
        sThread->pause();
    }
}

void MainWindow::on_actionStop_toggled(bool arg1)
{
    if(arg1){
        Status = STOP;
        ui->actionStop->setEnabled(false);
        ui->actionStart->setEnabled(true);
        ui->actionStart->setChecked(false);
        ui->actionSelectInterface->setEnabled(true);
        sThread->stop();
    }
}

void MainWindow::on_actionSelectInterface_triggered()
{
    selectIfDialog->changeLabel();
    selectIfDialog->show();//change the interface
}

void MainWindow::changeStatus(){
    QString *tmps = new QString("Now Interface is ");
    *tmps += QString(cap->nowDevice());
    statusLabel->setText(*tmps);

}

void MainWindow::on_actiontoButtom_toggled(bool arg1)
{
    toButtom = arg1;
}

void MainWindow::treeViewUpdate(QList<QStandardItem*> *treeItem){
    QStandardItem *Item;
    treeModel->clear();
    int index=0;
    QList<QStandardItem *>::iterator it=treeItem->begin();
    while((*it!=NULL)&&(it!=treeItem->end())){
        Item = new QStandardItem;
        Item = (*it)->clone();
        for(int i=0;i<((*it)->rowCount());i++){
            if((*it)->child(i)->rowCount()==0)Item->appendRow((*it)->child(i)->clone());
            else{
                Item->appendRow((*it)->child(i)->clone());
                for(int j=0;j<((*it)->child(i)->rowCount());j++)
                Item->child(i)->appendRow((*it)->child(i)->child(j)->clone());
            }
        }
        treeModel->setItem(index,Item);

        //treeModel->setItem(index,(*it));
        index++;
        it++;
    }
}

void MainWindow::filt(int rowNumber){
    if(fil.fstate())
        if(!(fil.launchOneFilter(**(tableViewModel->Data.begin()+rowNumber)))){
            ui->tableView->hideRow(rowNumber);
        }

}

void MainWindow::on_pushButton_clicked()
{
    for(int i=0;i<ui->tableView->model()->rowCount();i++) ui->tableView->showRow(i);

    if(ui->lineEdit->displayText().isEmpty()){
        QMessageBox::information(this,"","Filter Clear!",QMessageBox::Ok);
    }
    else if(fil.loadCommand(ui->lineEdit->displayText())){
        QList<SnifferData *>::iterator it = tableViewModel->Data.begin();
        for(int i=0;i<ui->tableView->model()->rowCount();i++,it++){
            if(!(fil.launchOneFilter(**it))){
                ui->tableView->hideRow(i);
            }
        }
    }
    else{
        QMessageBox::warning(this,"","Command Error",QMessageBox::Ok);
    }

}

void MainWindow::on_lineEdit_returnPressed()
{
    on_pushButton_clicked();
}
