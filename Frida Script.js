/*
 * Ultimate Snapchat SSL/Certificate Bypass Script
 * 
 * ## 👨‍💻 Author
 * 
 * **Riyad Mondol**
 * - GitHub: [@riyadmondol2006](https://github.com/riyadmondol2006)
 * - Website: [riyadm.com](https://riyadm.com)
 * - Reverse Engineering: [reversesio.com](http://reversesio.com/)
 * - Telegram: [@riyadmondol2006](https://t.me/riyadmondol2006)
 * - YouTube: [@reversesio](https://www.youtube.com/@reversesio)
 * 
 * For Security Research and Defensive Analysis Only
 */

// Global configuration
const CONFIG = {
    DEBUG: true,
    ENABLE_ANTI_DETECTION: true,
    ENABLE_NATIVE_HOOKS: true,
    ENABLE_TRAFFIC_MONITORING: true,
    GADGET_MODE: false,
    APP_PACKAGE: "com.snapchat.android"
};

// Detect if running in Gadget mode
try {
    if (typeof rpc !== 'undefined') {
        CONFIG.GADGET_MODE = true;
        console.log("[*] Frida Gadget mode detected");
    }
} catch (e) {
    CONFIG.GADGET_MODE = false;
    console.log("[*] Standard Frida mode detected");
}

// Enhanced logging system
class Logger {
    static timestamp() {
        return new Date().toISOString().split('T')[1].slice(0, -5);
    }
    
    static log(message, type = 'info') {
        const icons = {
            'info': '[*]',
            'success': '[+]',
            'bypass': '[!]',
            'error': '[-]',
            'warning': '[?]',
            'debug': '[D]'
        };
        
        const icon = icons[type] || '[*]';
        const timestamp = this.timestamp();
        
        if (type === 'debug' && !CONFIG.DEBUG) return;
        
        console.log(`${icon} ${timestamp} ${message}`);
    }
    
    static info(msg) { this.log(msg, 'info'); }
    static success(msg) { this.log(msg, 'success'); }
    static bypass(msg) { this.log(msg, 'bypass'); }
    static error(msg) { this.log(msg, 'error'); }
    static warning(msg) { this.log(msg, 'warning'); }
    static debug(msg) { this.log(msg, 'debug'); }
}

Logger.info("Ultimate Snapchat SSL Bypass - Initializing...");
Logger.info(`Mode: ${CONFIG.GADGET_MODE ? 'Gadget' : 'CLI'}`);

// State management
const State = {
    javaHooksInstalled: false,
    nativeHooksInstalled: false,
    antiDetectionInstalled: false,
    monitoringInstalled: false,
    appReady: false
};

// Utility functions
const Utils = {
    // Safe class loading
    safeUse: function(className) {
        try {
            return Java.use(className);
        } catch (e) {
            Logger.debug(`Class not found: ${className}`);
            return null;
        }
    },
    
    // Wait for module with timeout
    waitForModule: function(moduleName, timeout = 30000) {
        return new Promise((resolve, reject) => {
            const startTime = Date.now();
            const checkModule = setInterval(() => {
                const module = Process.findModuleByName(moduleName);
                if (module) {
                    clearInterval(checkModule);
                    Logger.success(`Module ${moduleName} loaded at: ${module.base}`);
                    resolve(module);
                } else if (Date.now() - startTime > timeout) {
                    clearInterval(checkModule);
                    reject(new Error(`Module ${moduleName} not found within ${timeout}ms`));
                }
            }, 100);
        });
    },
    
    // Pattern search with error handling
    findPattern: function(module, pattern) {
        try {
            const results = Memory.scanSync(module.base, module.size, pattern);
            return results.length > 0 ? results[0].address : null;
        } catch (e) {
            Logger.error(`Pattern search failed: ${e}`);
            return null;
        }
    },
    
    // Safe hooking wrapper
    safeHook: function(target, hookFunction, name) {
        try {
            hookFunction();
            Logger.success(`${name} hook installed`);
            return true;
        } catch (e) {
            Logger.error(`${name} hook failed: ${e}`);
            return false;
        }
    }
};

// Anti-detection mechanisms
class AntiDetection {
    static install() {
        if (State.antiDetectionInstalled || !CONFIG.ENABLE_ANTI_DETECTION) return;
        
        Logger.info("Installing anti-detection measures...");
        
        Java.perform(() => {
            // Hook file system checks
            Utils.safeHook(null, () => {
                const File = Utils.safeUse("java.io.File");
                if (File) {
                    File.exists.implementation = function() {
                        const name = this.getName();
                        const suspiciousNames = ['frida', 'gum', 'xposed', 'substrate', 'magisk'];
                        
                        if (suspiciousNames.some(sus => name.toLowerCase().includes(sus))) {
                            Logger.bypass(`Blocked file check for: ${name}`);
                            return false;
                        }
                        return this.exists();
                    };
                }
            }, "File.exists anti-detection");
            
            // Hook process checks
            Utils.safeHook(null, () => {
                const Runtime = Utils.safeUse("java.lang.Runtime");
                if (Runtime) {
                    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
                        if (cmd.includes('ps') || cmd.includes('frida') || cmd.includes('gum')) {
                            Logger.bypass(`Blocked command: ${cmd}`);
                            return this.exec("echo");
                        }
                        return this.exec(cmd);
                    };
                }
            }, "Runtime.exec anti-detection");
            
            // Hook stack trace checks
            Utils.safeHook(null, () => {
                const Thread = Utils.safeUse("java.lang.Thread");
                if (Thread) {
                    Thread.currentThread.implementation = function() {
                        const thread = this.currentThread();
                        const originalGetStackTrace = thread.getStackTrace;
                        
                        thread.getStackTrace = function() {
                            const stack = originalGetStackTrace.call(this);
                            // Filter out Frida-related stack frames
                            return stack.filter(frame => {
                                const className = frame.getClassName();
                                return !className.includes('frida') && !className.includes('gum');
                            });
                        };
                        
                        return thread;
                    };
                }
            }, "Thread.getStackTrace anti-detection");
            
            // Hook debug checks
            Utils.safeHook(null, () => {
                const Debug = Utils.safeUse("android.os.Debug");
                if (Debug) {
                    Debug.isDebuggerConnected.implementation = function() {
                        Logger.bypass("Debug.isDebuggerConnected bypassed");
                        return false;
                    };
                }
            }, "Debug.isDebuggerConnected anti-detection");
        });
        
        State.antiDetectionInstalled = true;
        Logger.success("Anti-detection measures installed");
    }
}

// Comprehensive SSL bypass
class SSLBypass {
    static installJavaHooks() {
        if (State.javaHooksInstalled) return;
        
        Logger.info("Installing comprehensive Java SSL hooks...");
        
        Java.perform(() => {
            // Universal TrustManager bypass
            Utils.safeHook(null, () => {
                const X509TrustManager = Utils.safeUse('javax.net.ssl.X509TrustManager');
                const SSLContext = Utils.safeUse('javax.net.ssl.SSLContext');
                
                if (X509TrustManager && SSLContext) {
                    const TrustManager = Java.registerClass({
                        name: 'com.research.universal.TrustManager',
                        implements: [X509TrustManager],
                        methods: {
                            checkClientTrusted: function() {
                                Logger.bypass("Universal TrustManager.checkClientTrusted bypassed");
                            },
                            checkServerTrusted: function() {
                                Logger.bypass("Universal TrustManager.checkServerTrusted bypassed");
                            },
                            getAcceptedIssuers: function() {
                                return [];
                            }
                        }
                    });
                    
                    const trustManagers = [TrustManager.$new()];
                    const sslContextInit = SSLContext.init.overload(
                        '[Ljavax.net.ssl.KeyManager;', 
                        '[Ljavax.net.ssl.TrustManager;', 
                        'java.security.SecureRandom'
                    );
                    
                    sslContextInit.implementation = function(keyManager, trustManager, secureRandom) {
                        Logger.bypass("SSLContext.init bypassed with universal TrustManager");
                        sslContextInit.call(this, keyManager, trustManagers, secureRandom);
                    };
                }
            }, "Universal TrustManager");
            
            // Android TrustManagerImpl (Android 7+)
            Utils.safeHook(null, () => {
                const TrustManagerImpl = Utils.safeUse('com.android.org.conscrypt.TrustManagerImpl');
                const ArrayList = Utils.safeUse("java.util.ArrayList");
                
                if (TrustManagerImpl && ArrayList) {
                    TrustManagerImpl.checkTrustedRecursive.implementation = function() {
                        Logger.bypass("TrustManagerImpl.checkTrustedRecursive bypassed");
                        return ArrayList.$new();
                    };
                    
                    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host) {
                        Logger.bypass(`TrustManagerImpl.verifyChain bypassed for: ${host}`);
                        return untrustedChain;
                    };
                }
            }, "TrustManagerImpl");
            
            // X509TrustManagerExtensions (Android specific)
            Utils.safeHook(null, () => {
                const X509TrustManagerExtensions = Utils.safeUse("android.net.http.X509TrustManagerExtensions");
                const ArrayList = Utils.safeUse("java.util.ArrayList");
                
                if (X509TrustManagerExtensions && ArrayList) {
                    X509TrustManagerExtensions.checkServerTrusted.overload(
                        '[Ljava.security.cert.X509Certificate;', 
                        'java.lang.String', 
                        'java.lang.String'
                    ).implementation = function(chain, authType, host) {
                        Logger.bypass(`X509TrustManagerExtensions bypassed for: ${host}`);
                        return ArrayList.$new();
                    };
                }
            }, "X509TrustManagerExtensions");
            
            // OkHttp Certificate Pinning (all variants)
            const okHttpHooks = [
                { clazz: 'okhttp3.CertificatePinner', method: 'check', params: ['java.lang.String', 'java.util.List'] },
                { clazz: 'okhttp3.CertificatePinner', method: 'check', params: ['java.lang.String', 'java.security.cert.Certificate'] },
                { clazz: 'okhttp3.CertificatePinner', method: 'check', params: ['java.lang.String', '[Ljava.security.cert.Certificate;'] },
                { clazz: 'okhttp3.CertificatePinner', method: 'check$okhttp', params: ['java.lang.String', 'kotlin.jvm.functions.Function0'] }
            ];
            
            okHttpHooks.forEach(hook => {
                Utils.safeHook(null, () => {
                    const clazz = Utils.safeUse(hook.clazz);
                    if (clazz) {
                        let method;
                        if (hook.params) {
                            method = clazz[hook.method].overload(...hook.params);
                        } else {
                            method = clazz[hook.method];
                        }
                        
                        method.implementation = function() {
                            const hostname = arguments[0];
                            Logger.bypass(`OkHttp ${hook.method} bypassed for: ${hostname}`);
                            return;
                        };
                    }
                }, `OkHttp ${hook.method}`);
            });
            
            // HostnameVerifier bypass
            Utils.safeHook(null, () => {
                const HostnameVerifier = Utils.safeUse("javax.net.ssl.HostnameVerifier");
                if (HostnameVerifier) {
                    HostnameVerifier.verify.implementation = function(hostname) {
                        Logger.bypass(`HostnameVerifier bypassed for: ${hostname}`);
                        return true;
                    };
                }
            }, "HostnameVerifier");
            
            // HttpsURLConnection bypasses
            const httpsUrlMethods = [
                'setDefaultHostnameVerifier',
                'setSSLSocketFactory',
                'setHostnameVerifier',
                'setDefaultSSLSocketFactory'
            ];
            
            httpsUrlMethods.forEach(methodName => {
                Utils.safeHook(null, () => {
                    const HttpsURLConnection = Utils.safeUse("javax.net.ssl.HttpsURLConnection");
                    if (HttpsURLConnection && HttpsURLConnection[methodName]) {
                        HttpsURLConnection[methodName].implementation = function() {
                            Logger.bypass(`HttpsURLConnection.${methodName} bypassed`);
                            return;
                        };
                    }
                }, `HttpsURLConnection.${methodName}`);
            });
            
            // WebView SSL error bypass
            Utils.safeHook(null, () => {
                const WebViewClient = Utils.safeUse("android.webkit.WebViewClient");
                if (WebViewClient) {
                    WebViewClient.onReceivedSslError.overload(
                        'android.webkit.WebView', 
                        'android.webkit.SslErrorHandler', 
                        'android.net.http.SslError'
                    ).implementation = function(view, handler) {
                        Logger.bypass("WebView SSL error bypassed");
                        handler.proceed();
                    };
                }
            }, "WebViewClient SSL");
            
            // Network Security Config bypass
            Utils.safeHook(null, () => {
                const NetworkSecurityConfig = Utils.safeUse("android.security.net.config.NetworkSecurityConfig");
                if (NetworkSecurityConfig) {
                    NetworkSecurityConfig.isCleartextTrafficPermitted.implementation = function() {
                        Logger.bypass("NetworkSecurityConfig.isCleartextTrafficPermitted bypassed");
                        return true;
                    };
                }
            }, "NetworkSecurityConfig");
            
            // Conscrypt bypasses
            const conscryptClasses = [
                'com.android.org.conscrypt.OpenSSLSocketImpl',
                'com.android.org.conscrypt.OpenSSLEngineSocketImpl',
                'com.android.org.conscrypt.CertPinManager'
            ];
            
            conscryptClasses.forEach(className => {
                Utils.safeHook(null, () => {
                    const clazz = Utils.safeUse(className);
                    if (clazz) {
                        if (clazz.verifyCertificateChain) {
                            clazz.verifyCertificateChain.implementation = function() {
                                Logger.bypass(`${className}.verifyCertificateChain bypassed`);
                                return;
                            };
                        }
                        if (clazz.isChainValid) {
                            clazz.isChainValid.implementation = function() {
                                Logger.bypass(`${className}.isChainValid bypassed`);
                                return true;
                            };
                        }
                    }
                }, className.split('.').pop());
            });
            
            // Dynamic SSL exception patcher
            Utils.safeHook(null, () => {
                const SSLPeerUnverifiedException = Utils.safeUse('javax.net.ssl.SSLPeerUnverifiedException');
                if (SSLPeerUnverifiedException) {
                    SSLPeerUnverifiedException.$init.implementation = function(str) {
                        Logger.bypass("SSL verification failure detected, auto-patching...");
                        
                        try {
                            const stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
                            const exceptionIndex = stackTrace.findIndex(stack =>
                                stack.getClassName() === "javax.net.ssl.SSLPeerUnverifiedException"
                            );
                            const callingStack = stackTrace[exceptionIndex + 1];
                            const className = callingStack.getClassName();
                            const methodName = callingStack.getMethodName();
                            
                            const callingClass = Utils.safeUse(className);
                            if (callingClass && callingClass[methodName] && !callingClass[methodName].implementation) {
                                const method = callingClass[methodName];
                                const returnType = method.returnType.type;
                                
                                method.implementation = function() {
                                    Logger.bypass(`Auto-patched ${className}.${methodName}`);
                                    return returnType === 'void' ? undefined : null;
                                };
                            }
                        } catch (e) {
                            Logger.debug(`Auto-patch failed: ${e}`);
                        }
                        
                        return this.$init(str);
                    };
                }
            }, "SSL Exception Auto-patcher");
        });
        
        State.javaHooksInstalled = true;
        Logger.success("Java SSL hooks installed successfully");
    }
    
    static installSnapchatSpecificHooks() {
        Logger.info("Installing Snapchat-specific hooks...");
        
        Java.perform(() => {
            // Delay for Snapchat classes to load
            setTimeout(() => {
                // Snapchat Certificate Roots
                Utils.safeHook(null, () => {
                    const CertificateRoots = Utils.safeUse("com.snapchat.client.certificates.CertificateRoots");
                    if (CertificateRoots) {
                        CertificateRoots.getCertificates.implementation = function() {
                            Logger.bypass("Snapchat CertificateRoots.getCertificates bypassed");
                            const result = this.getCertificates();
                            Logger.debug(`Original certificates: ${result ? result.length : 0}`);
                            return result;
                        };
                    }
                }, "Snapchat CertificateRoots");
                
                // Snapchat SSL classes from smali analysis
                const snapchatSSLClasses = ["CQ", "MLc", "IRc"];
                snapchatSSLClasses.forEach(className => {
                    Utils.safeHook(null, () => {
                        const clazz = Utils.safeUse(className);
                        if (clazz) {
                            Logger.success(`Found Snapchat SSL class: ${className}`);
                            
                            // Hook common SSL methods
                            ['checkServerTrusted', 'verify', 'isValid'].forEach(methodName => {
                                if (clazz[methodName]) {
                                    clazz[methodName].implementation = function() {
                                        Logger.bypass(`Snapchat ${className}.${methodName} bypassed`);
                                        return this[methodName].apply(this, arguments);
                                    };
                                }
                            });
                        }
                    }, `Snapchat ${className}`);
                });
            }, 5000);
        });
    }
    
    static installNativeHooks() {
        if (State.nativeHooksInstalled || !CONFIG.ENABLE_NATIVE_HOOKS) return;
        
        Logger.info("Installing native library hooks...");
        
        // Snapchat native patterns (from GitHub script analysis)
        const patterns = {
            arm64: 'fd 7b ba a9 fc 6f 01 a9 fa 67 02 a9 f8 5f 03 a9 f6 57 04 a9 f4 4f 05 a9 fd 03 00 91 ff 43 0e d1 53',
            arm: '2d e9 f0 4f ad f5 0b 7d 81 46 b5 48'
        };
        
        Utils.waitForModule("libclient.so").then(lib => {
            Logger.info("Setting up native certificate pinning bypass...");
            
            // Try architecture-specific patterns
            const arch = Process.arch;
            const pattern = arch === 'arm64' ? patterns.arm64 : patterns.arm;
            const address = Utils.findPattern(lib, pattern);
            
            if (address) {
                try {
                    Interceptor.attach(address, {
                        onEnter: function() {
                            Logger.bypass("Native certificate pinning function intercepted");
                        },
                        onLeave: function(retval) {
                            // Force success return
                            retval.replace(ptr(0x0));
                            Logger.bypass("Native certificate pinning bypassed");
                        }
                    });
                    Logger.success(`Native pinning hook installed at: ${address}`);
                } catch (e) {
                    Logger.error(`Native pinning hook failed: ${e}`);
                }
            } else {
                Logger.warning("Native pinning pattern not found, using fallback methods");
            }
            
            // Hook OpenSSL functions
            const sslFunctions = [
                "SSL_CTX_set_verify",
                "SSL_get_verify_result",
                "SSL_CTX_set_cert_verify_callback",
                "SSL_set_verify"
            ];
            
            sslFunctions.forEach(funcName => {
                try {
                    const funcAddr = Module.findExportByName("libclient.so", funcName);
                    if (funcAddr) {
                        Interceptor.attach(funcAddr, {
                            onEnter: function(args) {
                                Logger.debug(`${funcName} called`);
                                if (funcName.includes("set_verify")) {
                                    args[1] = ptr(0x00); // SSL_VERIFY_NONE
                                }
                            },
                            onLeave: function(retval) {
                                if (funcName === "SSL_get_verify_result") {
                                    retval.replace(ptr(0x0)); // X509_V_OK
                                    Logger.bypass(`${funcName} result modified to success`);
                                }
                            }
                        });
                        Logger.success(`Hooked ${funcName}`);
                    }
                } catch (e) {
                    Logger.debug(`Failed to hook ${funcName}: ${e}`);
                }
            });
            
            // Search for certificate validation strings
            const certStrings = [
                "tls.cert.pinned_key_not_in_cert_chain",
                "pin-sha256=",
                "HPKP violation",
                "certificate verify failed"
            ];
            
            certStrings.forEach(str => {
                try {
                    Memory.scan(lib.base, lib.size, str, {
                        onMatch: function(address) {
                            Logger.success(`Found cert validation string: ${str} at ${address}`);
                            return 'stop';
                        },
                        onError: function(reason) {
                            Logger.debug(`Memory scan failed for ${str}: ${reason}`);
                        }
                    });
                } catch (e) {
                    Logger.debug(`Memory scan error for ${str}: ${e}`);
                }
            });
            
            State.nativeHooksInstalled = true;
            Logger.success("Native hooks installation completed");
        }).catch(e => {
            Logger.warning(`libclient.so not found: ${e}`);
            State.nativeHooksInstalled = true; // Don't block other functionality
        });
    }
}

// Traffic monitoring and debugging
class TrafficMonitor {
    static install() {
        if (State.monitoringInstalled || !CONFIG.ENABLE_TRAFFIC_MONITORING) return;
        
        Logger.info("Installing traffic monitoring...");
        
        Java.perform(() => {
            // Monitor URL connections
            Utils.safeHook(null, () => {
                const URL = Utils.safeUse("java.net.URL");
                if (URL) {
                    URL.openConnection.overload().implementation = function() {
                        const connection = this.openConnection();
                        const url = this.toString();
                        
                        if (url.includes("snap") || url.includes("https://")) {
                            Logger.info(`Network connection: ${url}`);
                        }
                        
                        return connection;
                    };
                }
            }, "URL monitoring");
            
            // Monitor HttpURLConnection
            Utils.safeHook(null, () => {
                const HttpURLConnection = Utils.safeUse("java.net.HttpURLConnection");
                if (HttpURLConnection) {
                    HttpURLConnection.connect.implementation = function() {
                        const url = this.getURL().toString();
                        Logger.debug(`HTTP connection: ${url}`);
                        return this.connect();
                    };
                }
            }, "HttpURLConnection monitoring");
            
            // Monitor OkHttp requests
            Utils.safeHook(null, () => {
                const OkHttpClient = Utils.safeUse("okhttp3.OkHttpClient");
                if (OkHttpClient) {
                    OkHttpClient.newCall.implementation = function(request) {
                        const url = request.url().toString();
                        Logger.info(`OkHttp request: ${url}`);
                        return this.newCall(request);
                    };
                }
            }, "OkHttp monitoring");
        });
        
        State.monitoringInstalled = true;
        Logger.success("Traffic monitoring installed");
    }
}

// Main initialization function
function initialize() {
    Logger.info("=== Ultimate Snapchat SSL Bypass ===");
    Logger.info(`Architecture: ${Process.arch}`);
    Logger.info(`Platform: ${Process.platform}`);
    
    // Install anti-detection first
    AntiDetection.install();
    
    // Install SSL bypasses
    SSLBypass.installJavaHooks();
    SSLBypass.installSnapchatSpecificHooks();
    
    // Install native hooks after delay
    setTimeout(() => {
        SSLBypass.installNativeHooks();
    }, 3000);
    
    // Install traffic monitoring
    setTimeout(() => {
        TrafficMonitor.install();
    }, 5000);
    
    // Status report
    setTimeout(() => {
        Logger.info("=== Installation Status ===");
        Logger.info(`Java hooks: ${State.javaHooksInstalled ? '✓' : '✗'}`);
        Logger.info(`Native hooks: ${State.nativeHooksInstalled ? '✓' : '✗'}`);
        Logger.info(`Anti-detection: ${State.antiDetectionInstalled ? '✓' : '✗'}`);
        Logger.info(`Monitoring: ${State.monitoringInstalled ? '✓' : '✗'}`);
        Logger.info("=== Ready for Traffic Capture ===");
        Logger.success("Configure your proxy and start capturing!");
        Logger.info("Recommended tools: Burp Suite, OWASP ZAP, mitmproxy");
    }, 10000);
}

// Gadget-specific initialization
if (CONFIG.GADGET_MODE) {
    // For Gadget mode, initialize immediately
    setTimeout(initialize, 1000);
} else {
    // For CLI mode, wait for Java to be available
    Java.perform(() => {
        setTimeout(initialize, 2000);
    });
}

// Export functions for Gadget mode
if (CONFIG.GADGET_MODE && typeof rpc !== 'undefined') {
    rpc.exports = {
        init: initialize,
        getStatus: () => State,
        toggleDebug: () => { CONFIG.DEBUG = !CONFIG.DEBUG; },
        toggleAntiDetection: () => { CONFIG.ENABLE_ANTI_DETECTION = !CONFIG.ENABLE_ANTI_DETECTION; }
    };
}

Logger.info("Ultimate Snapchat SSL Bypass loaded successfully");
Logger.info("Use with: frida -U -f com.snapchat.android -l script.js --no-pause");
Logger.info("Or inject into APK for Gadget mode");
if (Java.available) {
    Java.perform(function() {
        var context = Java.use('android.app.ActivityThread')
            .currentApplication()
            .getApplicationContext();
        Java.scheduleOnMainThread(function() {
            var toast = Java.use("android.widget.Toast");
            toast.makeText(Java.use("android.app.ActivityThread")
                .currentApplication()
                .getApplicationContext(), Java.use("java.lang.String")
                .$new("frida loaded"), 1)
                .show();
        });
    });
}