/**
 * DarkSword 动态选择器系统测试脚本
 * 
 * 验证 ExploitSelector、FallbackExecutor 和 MetricCollector 的集成
 */

(function() {
  'use strict';
  
  console.log('=== DarkSword Dynamic Selector Test Suite ===\n');
  
  const tests = {
    passed: 0,
    failed: 0,
    results: []
  };
  
  function assert(condition, message) {
    if (condition) {
      tests.passed++;
      tests.results.push(`✓ ${message}`);
      console.log(`✓ ${message}`);
    } else {
      tests.failed++;
      tests.results.push(`✗ ${message}`);
      console.error(`✗ ${message}`);
    }
  }
  
  function testModuleLoading() {
    console.log('\n[1] Module Loading Tests');
    console.log('─────────────────────────');
    
    assert(
      typeof ExploitSelector === 'function',
      'ExploitSelector class loaded'
    );
    
    assert(
      typeof FallbackExecutor === 'function',
      'FallbackExecutor class loaded'
    );
    
    assert(
      typeof MetricCollector === 'function',
      'MetricCollector class loaded'
    );
    
    assert(
      typeof window.exploitSelector === 'object',
      'Global exploitSelector instance exists'
    );
    
    assert(
      typeof window.fallbackExecutor === 'object',
      'Global fallbackExecutor instance exists'
    );
    
    assert(
      typeof window.metricCollector === 'object',
      'Global metricCollector instance exists'
    );
  }
  
  function testExploitRegistry() {
    console.log('\n[2] Exploit Registry Tests');
    console.log('─────────────────────────');
    
    assert(
      Array.isArray(window.EXPLOIT_REGISTRY),
      'EXPLOIT_REGISTRY is array'
    );
    
    assert(
      window.EXPLOIT_REGISTRY.length > 0,
      `EXPLOIT_REGISTRY contains ${window.EXPLOIT_REGISTRY.length} candidates`
    );
    
    assert(
      typeof window.FALLBACK_CHAINS === 'object',
      'FALLBACK_CHAINS configuration exists'
    );
    
    const selector = window.exploitSelector;
    assert(
      selector.candidates.length === window.EXPLOIT_REGISTRY.length,
      `All ${selector.candidates.length} exploits registered in selector`
    );
  }
  
  function testContextSetup() {
    console.log('\n[3] Context Setup Tests');
    console.log('─────────────────────────');
    
    const selector = window.exploitSelector;
    
    const testContext = {
      iosVersion: '18.6.1',
      build: '22F82',
      device: 'iPhone16,1',
      capabilities: {
        wifi: true,
        bt: false
      }
    };
    
    selector.setContext(testContext);
    
    assert(
      selector.context !== null,
      'Context set successfully'
    );
    
    assert(
      selector.context.iosVersion === '18.6.1',
      `iOS version: ${selector.context.iosVersion}`
    );
    
    assert(
      selector.context.capabilities.wifi === true,
      'WiFi capability detected'
    );
  }
  
  function testConstraintMatching() {
    console.log('\n[4] Constraint Matching Tests');
    console.log('─────────────────────────');
    
    const selector = window.exploitSelector;
    
    // 测试版本约束
    const exploit1 = {
      id: 'TEST-1',
      minIOS: '18.0',
      maxIOS: '18.7',
      requiresWiFi: false,
      requiresBT: false
    };
    
    const context1 = {
      iosVersion: '18.6.1',
      capabilities: { wifi: true, bt: false }
    };
    
    assert(
      selector.matchesConstraints(exploit1, context1),
      'Version constraint matching works (18.6.1 in range 18.0-18.7)'
    );
    
    // 测试 WiFi 约束
    const exploit2 = {
      id: 'TEST-2',
      minIOS: '17.0',
      maxIOS: '99.0',
      requiresWiFi: true,
      requiresBT: false
    };
    
    const context2 = {
      iosVersion: '18.6.1',
      capabilities: { wifi: false, bt: false }
    };
    
    assert(
      !selector.matchesConstraints(exploit2, context2),
      'WiFi constraint filtering works (requires WiFi but not available)'
    );
    
    // 测试版本范围外
    const exploit3 = {
      id: 'TEST-3',
      minIOS: '17.0',
      maxIOS: '18.3.1',
      requiresWiFi: false,
      requiresBT: false
    };
    
    assert(
      !selector.matchesConstraints(exploit3, context1),
      'Version out of range filtering works (18.6.1 > 18.3.1)'
    );
  }
  
  async function testSelection() {
    console.log('\n[5] Dynamic Selection Tests');
    console.log('─────────────────────────');
    
    const selector = window.exploitSelector;
    
    // 为 SANDBOX_ESCAPE 选择
    const selected = await selector.selectBest('SANDBOX_ESCAPE');
    
    assert(
      selected !== null,
      'Successfully selected an exploit for SANDBOX_ESCAPE'
    );
    
    if (selected) {
      assert(
        selected.targetStage === 'SANDBOX_ESCAPE',
        `Selected exploit targets correct stage: ${selected.id}`
      );
      
      const score = selector.scoreExploit(selected, selector.context);
      assert(
        score > 0 && score <= 2,
        `Exploit score is valid: ${score.toFixed(3)}`
      );
    }
  }
  
  function testHistoryRecording() {
    console.log('\n[6] History Recording Tests');
    console.log('─────────────────────────');
    
    const selector = window.exploitSelector;
    const initialLength = selector.history.length;
    
    // 记录成功结果
    selector.recordResult('CVE-2026-20700', true, {
      duration: 58234,
      retries: 0
    });
    
    assert(
      selector.history.length === initialLength + 1,
      'History record added successfully'
    );
    
    const lastRecord = selector.history[selector.history.length - 1];
    assert(
      lastRecord.exploitId === 'CVE-2026-20700',
      `Last record has correct ID: ${lastRecord.exploitId}`
    );
    
    assert(
      lastRecord.success === true,
      'Last record has correct success status'
    );
    
    // 检查 localStorage 持久化
    const stored = localStorage.getItem('darksword_exploit_history');
    assert(
      stored !== null,
      'History persisted to localStorage'
    );
  }
  
  async function testFallbackExecution() {
    console.log('\n[7] Fallback Execution Tests');
    console.log('─────────────────────────');
    
    const executor = window.fallbackExecutor;
    
    // 创建测试方法
    let callCount = 0;
    const methods = [
      {
        fn: async () => { 
          callCount++;
          throw new Error('Method 1 failed'); 
        },
        id: 'TEST-METHOD-1',
        timeout: 1000,
        priority: 1
      },
      {
        fn: async () => { 
          callCount++;
          return { success: true, data: 'test' };
        },
        id: 'TEST-METHOD-2',
        timeout: 1000,
        priority: 2
      }
    ];
    
    const result = await executor.executeFallbackChain('TEST_STAGE', methods);
    
    assert(
      result.success === true,
      'Fallback chain succeeded with backup method'
    );
    
    assert(
      result.method.id === 'TEST-METHOD-2',
      'Correct fallback method was used'
    );
    
    assert(
      callCount === 2,
      'Both methods were attempted in order'
    );
  }
  
  async function testConcurrentExecution() {
    console.log('\n[8] Concurrent Execution Tests');
    console.log('─────────────────────────');
    
    const executor = window.fallbackExecutor;
    
    let method1Started = false;
    let method2Started = false;
    
    const methods = [
      {
        fn: async () => {
          method1Started = true;
          await new Promise(r => setTimeout(r, 500));
          return { data: 'slow method' };
        },
        id: 'SLOW-METHOD',
        timeout: 2000,
        priority: 1
      },
      {
        fn: async () => {
          method2Started = true;
          await new Promise(r => setTimeout(r, 100));
          return { data: 'fast method' };
        },
        id: 'FAST-METHOD',
        timeout: 2000,
        priority: 2
      }
    ];
    
    const startTime = Date.now();
    const result = await executor.executeStageConcurrent('TEST_CONCURRENT', methods);
    const duration = Date.now() - startTime;
    
    assert(
      result.success === true,
      'Concurrent execution succeeded'
    );
    
    assert(
      result.method.id === 'FAST-METHOD',
      'Fastest method won the race'
    );
    
    assert(
      duration < 300,
      `Completed in ${duration}ms (faster method finished first)`
    );
    
    assert(
      method1Started && method2Started,
      'Both methods started concurrently'
    );
  }
  
  async function testMetricCollection() {
    console.log('\n[9] Metric Collection Tests');
    console.log('─────────────────────────');
    
    const collector = window.metricCollector;
    const initialBufferLength = collector.buffer.length;
    
    // 收集测试 metric
    collector.collect('test_event', {
      testData: 'value',
      number: 123
    });
    
    assert(
      collector.buffer.length === initialBufferLength + 1,
      'Metric added to buffer'
    );
    
    const lastMetric = collector.buffer[collector.buffer.length - 1];
    assert(
      lastMetric.event === 'test_event',
      'Metric has correct event type'
    );
    
    assert(
      lastMetric.sessionId === collector.sessionId,
      'Metric has correct session ID'
    );
    
    assert(
      typeof lastMetric.data.memoryPressure === 'object',
      'Metric includes memory pressure data'
    );
    
    // 测试统计
    if (collector.db) {
      const stats = await collector.getStats();
      assert(
        stats !== null,
        'Metric statistics retrieved successfully'
      );
      
      assert(
        stats.total >= 0,
        `Total metrics: ${stats.total}`
      );
    } else {
      console.warn('  ⚠ IndexedDB not available, skipping DB tests');
    }
  }
  
  function testOrchestratorIntegration() {
    console.log('\n[10] Orchestrator Integration Tests');
    console.log('─────────────────────────');
    
    const orchestrator = window.AttackChainOrchestrator;
    
    assert(
      typeof orchestrator === 'object',
      'AttackChainOrchestrator loaded'
    );
    
    assert(
      orchestrator.selector !== null,
      'Orchestrator has selector reference'
    );
    
    assert(
      orchestrator.executor !== null,
      'Orchestrator has executor reference'
    );
    
    assert(
      orchestrator.enhancedMode === true,
      'Enhanced mode is enabled'
    );
    
    assert(
      typeof orchestrator.executeStageWithFallback === 'function',
      'executeStageWithFallback method exists'
    );
  }
  
  // 运行所有测试
  async function runAllTests() {
    try {
      testModuleLoading();
      testExploitRegistry();
      testContextSetup();
      testConstraintMatching();
      await testSelection();
      testHistoryRecording();
      await testFallbackExecution();
      await testConcurrentExecution();
      await testMetricCollection();
      testOrchestratorIntegration();
      
      console.log('\n' + '='.repeat(50));
      console.log('Test Summary');
      console.log('='.repeat(50));
      console.log(`Passed: ${tests.passed}`);
      console.log(`Failed: ${tests.failed}`);
      console.log(`Total:  ${tests.passed + tests.failed}`);
      
      if (tests.failed === 0) {
        console.log('\n✓ All tests passed!');
      } else {
        console.log(`\n✗ ${tests.failed} test(s) failed`);
      }
      
      return tests;
      
    } catch (e) {
      console.error('\n✗ Test suite error:', e);
      return tests;
    }
  }
  
  // 自动运行或导出供手动调用
  if (typeof window !== 'undefined') {
    window.runDarkSwordTests = runAllTests;
    
    // 检查是否应该自动运行
    const params = new URLSearchParams(window.location.search);
    if (params.get('test') === 'selector') {
      console.log('Auto-running tests (triggered by ?test=selector)...\n');
      setTimeout(() => runAllTests(), 1000);
    } else {
      console.log('Tests loaded. Run with: window.runDarkSwordTests()');
      console.log('Or add ?test=selector to URL for auto-run\n');
    }
  }
  
})();

console.log('[Test Suite] Module loaded');