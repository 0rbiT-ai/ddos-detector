const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
    getInterfaces: () => ipcRenderer.invoke('get-interfaces'),
    startSystem: (config) => ipcRenderer.send('start-system', config),
    stopSystem: () => ipcRenderer.send('stop-system'),
    updateThreshold: (threshold) => ipcRenderer.send('update-threshold', threshold),
    startAttack: (config) => ipcRenderer.send('start-attack', config),
    onAnalysisResult: (callback) => ipcRenderer.on('analysis-result', (event, result) => callback(result)),
    onSnifferError: (callback) => ipcRenderer.on('sniffer-error', (event, error) => callback(error))
});
