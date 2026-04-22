// QLinux OTP カーネルモジュール
// XFRM IPsec暗号化をOTPエンジンに差し替え + netfilterフック
// [FIX #8] nf_register_net_hook()の戻り値チェックを追加

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/errno.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("QLinux Project");
MODULE_DESCRIPTION("OTP encryption via netfilter + XFRM (Phase1)");

static struct nf_hook_ops qlinux_nf_ops;

// TODO: Rust OTPエンジンとのFFIインターフェース
// extern int otp_engine_encrypt(uint8_t *data, size_t len, uint64_t *key_id_out);
// extern void otp_engine_key_consumed(uint64_t key_id);

static unsigned int qlinux_otp_hook(void *priv,
                                     struct sk_buff *skb,
                                     const struct nf_hook_state *state)
{
    if (!skb || !skb->data || skb->len == 0)
        return NF_ACCEPT;

    // TODO: Rust FFI経由でOTP暗号化
    // uint64_t key_id;
    // int ret = otp_engine_encrypt(skb->data, skb->len, &key_id);
    // if (ret < 0) {
    //     printk(KERN_ERR "QLinux: OTP暗号化失敗 (%d), パケットをドロップ\n", ret);
    //     return NF_DROP;  // 暗号化失敗時は平文送信しない
    // }

    return NF_ACCEPT;
}

static int __init qlinux_otp_init(void)
{
    int ret;

    qlinux_nf_ops.hook     = qlinux_otp_hook;
    qlinux_nf_ops.hooknum  = NF_INET_POST_ROUTING;
    qlinux_nf_ops.pf       = PF_INET;
    qlinux_nf_ops.priority = NF_IP_PRI_LAST;

    // [FIX #8] 戻り値チェック
    ret = nf_register_net_hook(&init_net, &qlinux_nf_ops);
    if (ret < 0) {
        printk(KERN_ERR "QLinux: netfilterフックの登録失敗 (ret=%d)\n", ret);
        return ret;
    }

    printk(KERN_INFO "QLinux OTP module loaded\n");
    return 0;
}

static void __exit qlinux_otp_exit(void)
{
    nf_unregister_net_hook(&init_net, &qlinux_nf_ops);
    printk(KERN_INFO "QLinux OTP module unloaded\n");
}

module_init(qlinux_otp_init);
module_exit(qlinux_otp_exit);
