const electron = require('electron');
const url = require('url');
const path = require('path');
const { ipcMain } = require('electron');
const ipc = ipcMain;

const {app, BrowserWindow} = electron;


let mainWindow;

// Listen for app to be ready
app.on('ready', function() {
    // Create new window
    mainWindow = new BrowserWindow({
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false,
        },
        width: 1200,
        height: 800,
        minWidth: 670,
        minHeight: 500,
        frame: false,
        transparent: true,
    });
    // Load html into window
    mainWindow.loadURL(url.format({
        pathname: path.join(__dirname, 'mainWindow.html'),
        protocol: 'file:',
        slashes: true,
    }));

    ipc.on('minimizeApp', () => {
        mainWindow.minimize();
    });
    ipc.on('maximizeApp', () => {
        if (mainWindow.isMaximized()) {
            mainWindow.restore();
        }
        else {
            mainWindow.maximize();
        }
    });
    ipc.on('closeApp', () => {
        mainWindow.close();
    });
});
