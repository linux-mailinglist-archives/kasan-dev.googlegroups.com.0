Return-Path: <kasan-dev+bncBCQPF57GUQHBBB6E4KOQMGQE3LP4AOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id B2D5366098D
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Jan 2023 23:34:49 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id h1-20020a4ad281000000b004cf6ab29266sf1174621oos.2
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Jan 2023 14:34:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673044488; cv=pass;
        d=google.com; s=arc-20160816;
        b=Axt+ZEVUOfMx51BMM+SRxENT93+vRa0EQqMlRWRz4xd+t7+E4Smh4EMig9W9b2BmaO
         DNGAZreJwEc24IyVbl3M/ZpdzeSjKoSrxAFK42rRRpJXIC0P+OmxKU8gx+2ZrPr7wGXq
         ZUfP4+5qD9b7lAqYawB7US3gD8Qv+CuR76CdoAG+H+hbc/Gk6uevPTrplDTzdcfg4qV4
         /b3T6q+Bj4YHADou0jHy3/3HCjXT7RSe7OBBrzADSwiZ5gqSKJURjFhEYx+sTMC9ratM
         X1sxcwvq5GGH4ChZlLS4x9Shv9ktTM76JQbjuPvij6A6DngkUkHDD5oeqjbN+9bvzXkc
         emAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id:date
         :mime-version:sender:dkim-signature;
        bh=u3crdimCjqzu5hCgZds+POL2q3SGY0OcgRU/4gUAFV0=;
        b=DXZDpysrl5NEbwo/zegcyTJxVFWr/cppBIPqzjSJPFtFVc2w+os0yZv/iMZ4DAVAqg
         dtYS+e8WDbdVnLK+EcM8Xy8N5VnPvwxXzKC4y1SHuvA40gPRvZkRfDqbFiW8uWbm93tu
         Mn8RqQRt0r+fhsvCnwlbwwHAijoWcQeZG8lUgG7cs1pRo3u3A53QS4e3mVqWUZWbvuUY
         6sJGyfoP2dTuEGzknJGBV2EFXvBmKUGL6oJ46PKIbJGWM9PSSOYRwW9bFy75DP3uNdRj
         RoqK6smi6jWGlJ3pQuc6Z6ca8i5rsehOle9+g6apFZDW+v0nAwjO2hkljZ3uBNl0j5dy
         jfxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3b6k4ywkbaficij4u55ybu992x.08805yecybw87dy7d.w86@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.72 as permitted sender) smtp.mailfrom=3B6K4YwkbAFICIJ4u55yBu992x.08805yECyBw87Dy7D.w86@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:message-id:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=u3crdimCjqzu5hCgZds+POL2q3SGY0OcgRU/4gUAFV0=;
        b=QI6vLcd3ShJlAHJrPfAQaw2+vmRyk3F6QgSKeKwwIIFvfsZjdG3Op23GUB+m5zeQ97
         B6s9RCAbnrawsPf6QR6S0w1ft1ajQd4rYdbjJrLe6Oes7NPrk6hNQKFSi05Bzy9wvgxZ
         FcesI0Ky2zi+miH472YVuM4xzRU9yIWsjcwbTctH2a8aoTcBAHqBlFix1J7rzOmzBNq1
         6GRzNg/UizL9JDUgIyfAaeTYvrw3sY/O7PxUG7cftvI1HahT/e4Fudw9BfBn2HJOIFOo
         QLgKmbXxGTs3bnWdaMjGCQwHwhHDWwoQSp0ZheyxJB8zYEnpct/nFBZ/q9RufUi7y6Dl
         dAow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :message-id:date:mime-version:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=u3crdimCjqzu5hCgZds+POL2q3SGY0OcgRU/4gUAFV0=;
        b=qACEkrVUON5OUej6KKVviUIvIC5JsudoC1KFL6C+kn8L4TVWArpmy377nD6CZWt8+t
         HGKzRpnKAE595ccKYAVBShK+hPI+KYK1l7eS7+DUW+USvpBI1EjfosZRo7+EpmEkRUAg
         xnS+fzX4KUE7E+apt30nhBHyAwEJwsSu2BujqrnYBpIRncavcGHXgqka1EvYvIxNYS4a
         00m+jwqJzL8ErxBbMeO2mFtICPD9c8RIJkkhcTIf3gX5Ex+jxk5Qee0O2tQ4U6UtN996
         /ZW4gxvUm9m3J5g20m9mATnfxolWCxI4C7KyLI3axZjIlcT/EsYB/hy+4yIwfODPSHAE
         SEvw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpEC+hRSvadaAbfIuGW+UHlI33mOjjMruzKfmVEq+7M8r+tRILv
	OFO4FB1A1S41X75h6Vv6BYI=
X-Google-Smtp-Source: AMrXdXtLffNygaINMl7850bqzqUlWxxkjpbpDTrh5UGhvCsCAx7HAPqdCGUCZADhX4VI3Q2ORnxVXQ==
X-Received: by 2002:a05:6870:56a3:b0:144:d62b:6bfb with SMTP id p35-20020a05687056a300b00144d62b6bfbmr4482326oao.287.1673044488013;
        Fri, 06 Jan 2023 14:34:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1690:b0:363:22a6:79a9 with SMTP id
 bb16-20020a056808169000b0036322a679a9ls127347oib.0.-pod-prod-gmail; Fri, 06
 Jan 2023 14:34:47 -0800 (PST)
X-Received: by 2002:a05:6808:252:b0:35e:728c:6e1b with SMTP id m18-20020a056808025200b0035e728c6e1bmr23979499oie.26.1673044487407;
        Fri, 06 Jan 2023 14:34:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673044487; cv=none;
        d=google.com; s=arc-20160816;
        b=LkcnQ/UX6shi6levBnB87vmkDFtvZTSxplR2zPT7WNH2WV6gRSGrYKaNA55waHFeTr
         V9z5OS3KXTCAW8O5S14g/qP0I5RCMUmRAV92jkIyJDC1oassfDBg7Y9Cxc6KJLj3VgzG
         3L28T9TuH6q1ta1bBLj3WMD/cNDTKtB/eOop+XACXcohS09N6AIYZXypxHEYBZvtt+8q
         rYI4uoe1GogrvCtoG/rwAZH8otASMhsJ0rXZ0i/olKu3mIMaBXLjbmOpO3oWEThYZpr3
         eugBVaZvchd5X8Ei3aScsIKe1p5odn5ABji5w+7BKlGfVwOPFfhSe9sEOe88DfIokzZu
         MDRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:date:mime-version;
        bh=/VVxBlJtQV6v5OcAs8EWLg+XArUjMk64C2b0BsikPv8=;
        b=bdnvgs61N3hjzMp2ilo0HBikrmvBquLMwgsy+CtO/sDc0I3G0R8+LHvlmy1aAgn3Oz
         LrGSS9pZbu+e0aH6AE4tvBokeBvHOoi3lR0N5Zcjca9b+mUH0q3rw4I/M/R7dw3mLc7v
         XNdX7SDL4ba8jQfertpNeV83stRrnld0Re+aFK9NuJ22j9mi8nVmxgztPtq6PQeb0Ucz
         KAPwLQIAiSH6gB1fhkjJcnXeIWIGCSKqZlCsbgkVL/yh6bh9978b6dfBL29WLytlj7tR
         LBR4NhDSwULJD1zmd7ppiSz9nkBLM1jEqkt2YtqGLkBSCBXhv5vPQF5hGKus98xYIcni
         RAtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3b6k4ywkbaficij4u55ybu992x.08805yecybw87dy7d.w86@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.72 as permitted sender) smtp.mailfrom=3B6K4YwkbAFICIJ4u55yBu992x.08805yECyBw87Dy7D.w86@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-io1-f72.google.com (mail-io1-f72.google.com. [209.85.166.72])
        by gmr-mx.google.com with ESMTPS id e19-20020a544f13000000b0035c06b99516si243677oiy.3.2023.01.06.14.34.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Jan 2023 14:34:47 -0800 (PST)
Received-SPF: pass (google.com: domain of 3b6k4ywkbaficij4u55ybu992x.08805yecybw87dy7d.w86@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.72 as permitted sender) client-ip=209.85.166.72;
Received: by mail-io1-f72.google.com with SMTP id g11-20020a6be60b000000b006e2c707e565so1489093ioh.14
        for <kasan-dev@googlegroups.com>; Fri, 06 Jan 2023 14:34:47 -0800 (PST)
MIME-Version: 1.0
X-Received: by 2002:a6b:1406:0:b0:6e0:992:d816 with SMTP id
 6-20020a6b1406000000b006e00992d816mr4401619iou.77.1673044487069; Fri, 06 Jan
 2023 14:34:47 -0800 (PST)
Date: Fri, 06 Jan 2023 14:34:47 -0800
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <0000000000005875da05f1a006b3@google.com>
Subject: [syzbot] WARNING in __kfence_free (2)
From: syzbot <syzbot+a40ed4dfdfabdc0cdf9e@syzkaller.appspotmail.com>
To: akpm@linux-foundation.org, dvyukov@google.com, elver@google.com, 
	glider@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3b6k4ywkbaficij4u55ybu992x.08805yecybw87dy7d.w86@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.72 as permitted sender) smtp.mailfrom=3B6K4YwkbAFICIJ4u55yBu992x.08805yECyBw87Dy7D.w86@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Hello,

syzbot found the following issue on:

HEAD commit:    69b41ac87e4a Merge tag 'for-6.2-rc2-tag' of git://git.kern..
git tree:       upstream
console output: https://syzkaller.appspot.com/x/log.txt?x=11aacc94480000
kernel config:  https://syzkaller.appspot.com/x/.config?x=b3a84b3173b6e1cb
dashboard link: https://syzkaller.appspot.com/bug?extid=a40ed4dfdfabdc0cdf9e
compiler:       aarch64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2
userspace arch: arm64

Unfortunately, I don't have any reproducer for this issue yet.

IMPORTANT: if you fix the issue, please add the following tag to the commit:
Reported-by: syzbot+a40ed4dfdfabdc0cdf9e@syzkaller.appspotmail.com

------------[ cut here ]------------
WARNING: CPU: 0 PID: 3043 at mm/kfence/core.c:1059 __kfence_free+0x80/0xb4 mm/kfence/core.c:1059
Modules linked in:
CPU: 0 PID: 3043 Comm: syz-executor.1 Not tainted 6.2.0-rc2-syzkaller-00010-g69b41ac87e4a #0
Hardware name: linux,dummy-virt (DT)
pstate: 80400009 (Nzcv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--)
pc : __kfence_free+0x80/0xb4 mm/kfence/core.c:1059
lr : kfence_free include/linux/kfence.h:186 [inline]
lr : __slab_free+0x358/0x55c mm/slub.c:3588
sp : ffff80000aaeba20
x29: ffff80000aaeba20 x28: ffff00007b580c00 x27: ffff80000a383398
x26: f3ff000002c02a00 x25: ffff00007b580c00 x24: ffff00007b580c00
x23: ffff00007b580c00 x22: f9ff000005431f00 x21: ffff8000082328dc
x20: f3ff000002c02a00 x19: fffffc0001ed6000 x18: 0000000000000002
x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000
x14: 0000000000000001 x13: 000000000006ad0a x12: fdff000005cb9b24
x11: fdff000005cb9b00 x10: 0000000000000000 x9 : 0000000000000000
x8 : 0000000000000000 x7 : 0000000000000000 x6 : ffff80000a380000
x5 : ffff8000082328dc x4 : ffff80000a6311f8 x3 : ffff80000a380340
x2 : fdff000005cf7c00 x1 : ffff80000a642f70 x0 : ffff00007b580c00
Call trace:
 __kfence_free+0x80/0xb4 mm/kfence/core.c:1059
 kfence_free include/linux/kfence.h:186 [inline]
 __slab_free+0x358/0x55c mm/slub.c:3588
 do_slab_free mm/slub.c:3731 [inline]
 slab_free mm/slub.c:3788 [inline]
 __kmem_cache_free+0x2d0/0x2f0 mm/slub.c:3800
 kfree+0x60/0xb0 mm/slab_common.c:1020
 kvfree+0x3c/0x50 mm/util.c:627
 xt_free_table_info+0x78/0x90 net/netfilter/x_tables.c:1212
 __do_replace+0x260/0x330 net/ipv4/netfilter/ip_tables.c:1087
 do_replace net/ipv6/netfilter/ip6_tables.c:1157 [inline]
 do_ip6t_set_ctl+0x36c/0x4b4 net/ipv6/netfilter/ip6_tables.c:1639
 nf_setsockopt+0x68/0x94 net/netfilter/nf_sockopt.c:101
 ipv6_setsockopt+0x98/0xe4 net/ipv6/ipv6_sockglue.c:1028
 tcp_setsockopt+0x20/0x3c net/ipv4/tcp.c:3801
 sock_common_setsockopt+0x1c/0x2c net/core/sock.c:3664
 __sys_setsockopt+0xd4/0x1a0 net/socket.c:2246
 __do_sys_setsockopt net/socket.c:2257 [inline]
 __se_sys_setsockopt net/socket.c:2254 [inline]
 __arm64_sys_setsockopt+0x28/0x40 net/socket.c:2254
 __invoke_syscall arch/arm64/kernel/syscall.c:38 [inline]
 invoke_syscall+0x48/0x114 arch/arm64/kernel/syscall.c:52
 el0_svc_common.constprop.0+0x44/0xec arch/arm64/kernel/syscall.c:142
 do_el0_svc+0x38/0xc0 arch/arm64/kernel/syscall.c:197
 el0_svc+0x2c/0xb0 arch/arm64/kernel/entry-common.c:637
 el0t_64_sync_handler+0xb8/0xc0 arch/arm64/kernel/entry-common.c:655
 el0t_64_sync+0x19c/0x1a0 arch/arm64/kernel/entry.S:584
---[ end trace 0000000000000000 ]---


---
This report is generated by a bot. It may contain errors.
See https://goo.gl/tpsmEJ for more information about syzbot.
syzbot engineers can be reached at syzkaller@googlegroups.com.

syzbot will keep track of this issue. See:
https://goo.gl/tpsmEJ#status for how to communicate with syzbot.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0000000000005875da05f1a006b3%40google.com.
