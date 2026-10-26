/**
 * DarkSword 多路径 Fallback 执行器
 * 
 * 功能:
 * - 双轨并行执行：同时运行多个 exploit 方法，首个成功的获胜
 * - Fallback 链：主路径失败后自动降级到备选方案
 * - 超时控制：每个方法独立超时，避免长时间阻塞
 * - 结果记录：向 ExploitSelector 报告实际执行结果
 */

class FallbackExecutor {
  constructor(exploitSelector) {
    this.selector = exploitSelector;
    this.activeExecutions = new Map();
    this.cancelTokens = new Map();
    
    console.log('[FallbackExecutor] Initialized');
  }
  
  /**
   * 并发执行多个方法，返回首个成功的结果
   * @param {string} stageId - 阶段标识
   * @param {Array} methods - 方法数组，每个元素:
   *   - fn: 执行函数（async）
   *   - id: exploit ID
   *   - priority: 优先级
   *   - timeout: 超时时间（毫秒）
   * @returns {Object} - { success, method, result, duration, fallbackUsed }
   */
  async executeStageConcurrent(stageId, methods) {
    if (!methods || methods.length === 0) {
      return { success: false, error: 'No methods provided' };
    }
    
    console.log(`[FallbackExecutor] Stage ${stageId}: Executing ${methods.length} methods concurrently`);
    this.selector.sendMetric('stage_start', {
      stage: stageId,
      methodCount: methods.length,
      methods: methods.map(m => m.id)
    });
    
    const startTime = Date.now();
    let cancelOthers = false;
    const cancelToken = { cancelled: false };
    this.cancelTokens.set(stageId, cancelToken);
    
    // 为每个方法创建执行 Promise
    const promises = methods.map((method, index) => 
      this.executeWithTimeout(method.fn, method.timeout, method, cancelToken)
        .then(result => ({
          success: true,
          method,
          result,
          index,
          duration: Date.now() - startTime
        }))
        .catch(error => ({
          success: false,
          method,
          error: error.message || String(error),
          index,
          duration: Date.now() - startTime
        }))
    );
    
    // 使用 Promise.race 获取首个完成的结果
    const raceResult = await Promise.race(promises);
    
    // 如果首个结果成功，取消其他执行
    if (raceResult.success) {
      cancelToken.cancelled = true;
      console.log(`[FallbackExecutor] Stage ${stageId}: Method ${raceResult.method.id} succeeded in ${raceResult.duration}ms`);
      
      // 记录成功
      this.selector.recordResult(
        raceResult.method.id,
        true,
        {
          stage: stageId,
          duration: raceResult.duration,
          fallbackUsed: raceResult.index > 0
        }
      );
      
      this.selector.sendMetric('stage_complete', {
        stage: stageId,
        exploitId: raceResult.method.id,
        duration: raceResult.duration,
        totalRetries: 0,
        path: raceResult.index === 0 ? 'primary' : 'fallback'
      });
      
      return raceResult;
    }
    
    // 首个完成的失败了，等待其他方法
    console.log(`[FallbackExecutor] Stage ${stageId}: Method ${raceResult.method.id} failed, waiting for others...`);
    
    const allResults = await Promise.all(promises);
    
    // 查找首个成功的
    const successResult = allResults.find(r => r.success);
    
    if (successResult) {
      console.log(`[FallbackExecutor] Stage ${stageId}: Fallback method ${successResult.method.id} succeeded`);
      
      this.selector.recordResult(
        successResult.method.id,
        true,
        {
          stage: stageId,
          duration: successResult.duration,
          fallbackUsed: true
        }
      );
      
      this.selector.sendMetric('stage_complete', {
        stage: stageId,
        exploitId: successResult.method.id,
        duration: successResult.duration,
        totalRetries: successResult.index,
        path: 'fallback'
      });
      
      return successResult;
    }
    
    // 全部失败
    console.error(`[FallbackExecutor] Stage ${stageId}: All methods failed`);
    
    // 记录所有失败
    allResults.forEach(r => {
      this.selector.recordResult(
        r.method.id,
        false,
        {
          stage: stageId,
          duration: r.duration,
          error: r.error
        }
      );
    });
    
    this.selector.sendMetric('stage_failed', {
      stage: stageId,
      attempts: allResults.length,
      errors: allResults.map(r => ({ id: r.method.id, error: r.error }))
    });
    
    return {
      success: false,
      error: 'All concurrent methods failed',
      attempts: allResults.length,
      details: allResults
    };
  }
  
  /**
   * 执行 Fallback 链（顺序执行，主路径失败后依次尝试备选）
   * @param {string} stageId - 阶段标识
   * @param {Array} methods - 方法数组（按优先级排序）
   * @returns {Object} - 执行结果
   */
  async executeFallbackChain(stageId, methods) {
    if (!methods || methods.length === 0) {
      return { success: false, error: 'No methods provided' };
    }
    
    console.log(`[FallbackExecutor] Stage ${stageId}: Executing fallback chain (${methods.length} methods)`);
    this.selector.sendMetric('stage_start', {
      stage: stageId,
      methodCount: methods.length,
      mode: 'sequential_fallback',
      methods: methods.map(m => m.id)
    });
    
    let lastError = null;
    
    for (let i = 0; i < methods.length; i++) {
      const method = methods[i];
      const isPrimary = i === 0;
      const startTime = Date.now();
      
      console.log(`[FallbackExecutor] Attempting ${isPrimary ? 'primary' : 'fallback'} method: ${method.id}`);
      
      this.selector.sendMetric('exploit_attempt', {
        exploitId: method.id,
        stage: stageId,
        attemptNumber: i + 1,
        isPrimary,
        timeout: method.timeout
      });
      
      try {
        const result = await this.executeWithTimeout(method.fn, method.timeout, method);
        const duration = Date.now() - startTime;
        
        console.log(`[FallbackExecutor] Method ${method.id} succeeded in ${duration}ms`);
        
        this.selector.recordResult(
          method.id,
          true,
          {
            stage: stageId,
            duration,
            fallbackUsed: !isPrimary,
            attemptNumber: i + 1
          }
        );
        
        this.selector.sendMetric('stage_complete', {
          stage: stageId,
          exploitId: method.id,
          duration,
          totalRetries: i,
          path: isPrimary ? 'primary' : 'fallback'
        });
        
        return {
          success: true,
          method,
          result,
          duration,
          fallbackUsed: !isPrimary,
          attemptNumber: i + 1
        };
        
      } catch (error) {
        const duration = Date.now() - startTime;
        lastError = error.message || String(error);
        
        console.warn(`[FallbackExecutor] Method ${method.id} failed: ${lastError}`);
        
        this.selector.recordResult(
          method.id,
          false,
          {
            stage: stageId,
            duration,
            error: lastError,
            attemptNumber: i + 1
          }
        );
        
        this.selector.sendMetric('exploit_attempt', {
          exploitId: method.id,
          stage: stageId,
          success: false,
          duration,
          error: lastError,
          attemptNumber: i + 1
        });
        
        // 继续尝试下一个方法
        if (i < methods.length - 1) {
          console.log(`[FallbackExecutor] Falling back to next method...`);
        }
      }
    }
    
    // 全部失败
    console.error(`[FallbackExecutor] Stage ${stageId}: Fallback chain exhausted`);
    
    this.selector.sendMetric('stage_failed', {
      stage: stageId,
      attempts: methods.length,
      lastError
    });
    
    return {
      success: false,
      error: 'Fallback chain exhausted',
      lastError,
      attempts: methods.length
    };
  }
  
  /**
   * 带超时的执行包装
   */
  async executeWithTimeout(fn, timeout, method, cancelToken = null) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Timeout after ${timeout}ms`));
      }, timeout);
      
      // 定期检查取消标志
      let checkInterval = null;
      if (cancelToken) {
        checkInterval = setInterval(() => {
          if (cancelToken.cancelled) {
            clearTimeout(timer);
            clearInterval(checkInterval);
            reject(new Error('Cancelled by concurrent success'));
          }
        }, 100);
      }
      
      Promise.resolve(fn())
        .then(result => {
          clearTimeout(timer);
          if (checkInterval) clearInterval(checkInterval);
          resolve(result);
        })
        .catch(error => {
          clearTimeout(timer);
          if (checkInterval) clearInterval(checkInterval);
          reject(error);
        });
    });
  }
  
  /**
   * 获取内存压力信息（用于 metric）
   */
  getMemoryInfo() {
    if (typeof performance !== 'undefined' && performance.memory) {
      return {
        usedJSHeapSize: performance.memory.usedJSHeapSize,
        totalJSHeapSize: performance.memory.totalJSHeapSize,
        jsHeapSizeLimit: performance.memory.jsHeapSizeLimit,
        usedMB: Math.round(performance.memory.usedJSHeapSize / 1024 / 1024)
      };
    }
    return null;
  }
  
  /**
   * 取消指定阶段的执行
   */
  cancelStage(stageId) {
    const token = this.cancelTokens.get(stageId);
    if (token) {
      token.cancelled = true;
      console.log(`[FallbackExecutor] Cancelled stage: ${stageId}`);
    }
  }
  
  /**
   * 取消所有活跃执行
   */
  cancelAll() {
    this.cancelTokens.forEach((token, stageId) => {
      token.cancelled = true;
      console.log(`[FallbackExecutor] Cancelled stage: ${stageId}`);
    });
    this.cancelTokens.clear();
  }
}

// 全局实例
if (typeof window !== 'undefined') {
  window.FallbackExecutor = FallbackExecutor;
  
  // 如果已有 exploitSelector，自动创建 executor
  if (window.exploitSelector) {
    window.fallbackExecutor = new FallbackExecutor(window.exploitSelector);
    console.log('[FallbackExecutor] Global instance created at window.fallbackExecutor');
  }
}

console.log('[FallbackExecutor] Module loaded');