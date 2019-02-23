#ifndef DEBUG_HELPER
#define DEBUG_HELPER

	#ifndef ROOTKIT_DEBUG
		#define dbg_print(M, ...)
		#define dbg_err_print(M, ...)
	#else
		#define dbg_print(M, ...) printk(KERN_INFO "[+] Colman: " M "\n", ##__VA_ARGS__)
		#define dbg_err_print(M, ...) printk(KERN_INFO "[-] Colman (%s:%d): " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)
	#endif

#endif