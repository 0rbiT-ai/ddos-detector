import { app, BrowserWindow, ipcMain, dialog } from 'electron';
import { spawn } from 'child_process';
import path from 'path';
import os from 'os';
import fs from 'fs';

const __filename = new URL(import.meta.url).pathname;
const __dirname = path.dirname(__filename).replace(/^\\([A-Z]:)/, '$1');

let mainWindow;
let pythonSnifferProcess;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1000,
        height: 800,
        minWidth: 800,
        minHeight: 600,
        webPreferences: {
            preload: path.join(app.getAppPath(), 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
        },
    });

    mainWindow.loadFile('index.html');
}

ipcMain.handle('get-interfaces', () => {
    const interfaces = os.networkInterfaces();
    const result = [];
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                result.push({ name: name, ip: iface.address });
            }
        }
    }
    return result;
});

ipcMain.on('start-system', (event, config) => {
    startPythonSniffer(config);
});

ipcMain.on('stop-system', () => {
    if (pythonSnifferProcess) {
        pythonSnifferProcess.kill();
        pythonSnifferProcess = null;
        console.log('Sniffer process stopped by user.');
        if (mainWindow) {
            mainWindow.webContents.send('sniffer-error', 'System Stopped by User.');
        }
    }
});


ipcMain.on('update-threshold', (event, threshold) => {
    if (pythonSnifferProcess) {
        const command = JSON.stringify({ command: 'update_threshold', value: threshold }) + '\n';
        pythonSnifferProcess.stdin.write(command);
    }
});

ipcMain.on('start-attack', (event, config) => {
    startTrafficGenerator(config);
});

function startPythonSniffer(config) {
    if (pythonSnifferProcess) {
        pythonSnifferProcess.kill();
    }

    const pythonScript = path.join(app.getAppPath(), 'backend', 'sniffer_ml.py');
    const pythonExecutable = 'py';
    const pythonArguments = ['-3', pythonScript, '--interface', config.interface, '--threshold', config.ppsThreshold];

    pythonSnifferProcess = spawn(pythonExecutable, pythonArguments);

    console.log(`Starting Sniffer: ${pythonExecutable} ${pythonArguments.join(' ')}`);

    pythonSnifferProcess.stdout.on('data', (data) => {
        try {
            const message = data.toString().trim();
            // Handle multiple JSON objects in one chunk
            const lines = message.split('\n');
            lines.forEach(line => {
                if (line.trim()) {
                    try {
                        const analysisResult = JSON.parse(line);
                        if (mainWindow) {
                            mainWindow.webContents.send('analysis-result', analysisResult);
                        }
                    } catch (e) {
                        // Ignore non-JSON output
                    }
                }
            });
        } catch (e) {
            console.error('Error parsing sniffer output:', e);
        }
    });

    pythonSnifferProcess.stderr.on('data', (data) => {
        const errorMsg = data.toString().trim();
        console.error(`Sniffer Error Stream: ${errorMsg}`);
        if (mainWindow) {
            mainWindow.webContents.send('sniffer-error', errorMsg);
        }
    });

    pythonSnifferProcess.on('close', (code) => {
        const message = `Sniffer closed. Code: ${code}`;
        console.log(`Python process closed: ${code}`);
        if (mainWindow) {
            mainWindow.webContents.send('sniffer-error', message);
        }
    });
}

function startTrafficGenerator(config) {
    const pythonScript = path.join(app.getAppPath(), 'traffic_generator.py');
    const pythonExecutable = 'py';
    const args = ['-3', pythonScript, '--target-ip', config.targetIp, '--packets', config.packetCount];

    console.log(`Starting Generator: ${pythonExecutable} ${args.join(' ')}`);

    const genProcess = spawn(pythonExecutable, args);

    genProcess.stdout.on('data', (data) => {
        console.log(`Generator: ${data}`);
    });

    genProcess.stderr.on('data', (data) => {
        console.error(`Generator Error: ${data}`);
    });
}

app.on('will-quit', () => {
    if (pythonSnifferProcess) {
        pythonSnifferProcess.kill();
    }
});

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
    }
});
