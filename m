Return-Path: <kasan-dev+bncBCMIZB7QWENRBK6Z47XQKGQE2GHIATI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 2328F124264
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2019 10:09:01 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id t17sf804599ply.5
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2019 01:09:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576660139; cv=pass;
        d=google.com; s=arc-20160816;
        b=nPJ5AH448DtDCR5prOZFJX/gRmJsW00TwTXh7me+PAhGLvD3v0EpTDmzGYOiWhx8ek
         rFOwXvVendG30fIX03vz85GmuqgmG/8p2do+9lu1T3vRvwpMGR4W7zD9fCbav8jLNPBJ
         Uf5lcllD1HG12VWAEbQTptQfTS/BrRvL60ICHK8J59Uh2ia/trqJUFH+xAsAMhS+W8AN
         fRccsv5e5gG8z9AS89QqwReGmMZ+iQ7uYTEEhtRSzqFD+zLIuGs5jSYrBkqyig8QC75X
         OnlW2odkwkM4+vWKBhzkAJJNoQbU+LG9dkNwZuxv5VAaFr8g5foGADEPZU7+ugF0LHIX
         nocg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1uoHSvhHm/iGayPgrE42iajA0+KC0X5qV/dmobMSDBo=;
        b=X8iSwT/bfW4TRb14L5FxTS4rSq58DurDBxFhEu9ulr4NOQZmrf4F/h9yyhcOlrVpWy
         O1Nohb970Y0TwwZUdmF+JZrDon9iS6iF3KRSHTkPEwZmuRWdKDK3oa5+RAhPISWO2Ulg
         X9P3JGjLNrZGeFTppysJQZlgdDb42Lria+mTnk0opdT790vyqOkSIS2r675P6RISXcqV
         nQiDZUAXyYIRE88vx702ocjiF1DnfPx5xwAZ/JH2RCRvFyfqDziWDD65gwYWlBZvgjbM
         4dJbXJwUVSCoeloCsXHwAxN+4lS1jLGNoFUqMx6gB+UE6QpqeH8HmHlm13Lj2boLAJ3p
         EsIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nj0nK9hM;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1uoHSvhHm/iGayPgrE42iajA0+KC0X5qV/dmobMSDBo=;
        b=YHjgECc2Z6/UmdHlkMaHHPHUA1g1sW8N2fjv1gt+kNTtcEjVAL5AM43+LkRsKcqTwB
         tty6rGMiJwBXHs6UR54+hIh/1PncRgLBYqH/6rE3KynuhYZDRw/LyTxkhW8nECTI5QJJ
         Ne0iRtcPpurS84Y0h0/6YEFThI2sBZgZ3G6elBXP0+wzEx0bxXlJB3ViCZmGY69Lqe2M
         8o90u5M7m2LaxgIudnYXXnBsgzef0qAEaIk3NElZcl19OF0DblfIvUCZUy2rAORh8dG3
         AAxgttF4do9IqIomrFeFkKdQc2YEVbDVLJ5YixLRdIo+KEPSYPXkQQES03T9IBVwsz60
         7emg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1uoHSvhHm/iGayPgrE42iajA0+KC0X5qV/dmobMSDBo=;
        b=tf/UQDMR35WKxaC2bGd9PWopy/v5ksNRb3gvMJ4bdNySs/6048Py6m5ndPsQj9k9v8
         q0T1QO3EuITcT+p/iYSQNqqkVCzGMZD6iu0wCHEWH6vO/jVyKrn356vyeueI4gF6kLZd
         OilvqlNjD8M3O59tvZAhHs4J7PoXMsV5+7kwP5EbSpB95ke17hzkOZcezRlN4E7hV53p
         VMIOC40rQZsbvZ5Vhz+4mmMraaKH9QNJDqGy0NUQwTiS3hNmpHoC/6LSw1kKTcI6Zqm1
         uil+pXWrlRQv0cst9EVpDGTTOleWgrE1GdEAgJF4WGUC+gGlN0+jOEhmfVXKWi19m+2G
         OOEA==
X-Gm-Message-State: APjAAAXD3F+4aDo3FVDMFUN7/Ta0Jjs8jRyXiVUwgO9HuSVphchgIH60
	3/GsAwe9VyhKanOXakzJ7to=
X-Google-Smtp-Source: APXvYqwhNWc2tbRjaPv3aE7+mFmR0wX9ghh9sYk9b2YHFj9yv7X5FihStYR7Zsy+5XUlZvkL4KkrDg==
X-Received: by 2002:a17:90a:a010:: with SMTP id q16mr1566556pjp.115.1576660139265;
        Wed, 18 Dec 2019 01:08:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1853:: with SMTP id 80ls409015pfy.1.gmail; Wed, 18 Dec
 2019 01:08:58 -0800 (PST)
X-Received: by 2002:a63:2842:: with SMTP id o63mr1847836pgo.317.1576660138828;
        Wed, 18 Dec 2019 01:08:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576660138; cv=none;
        d=google.com; s=arc-20160816;
        b=eIMxYuDVtuqj1wJEQMQJ1X9v6WRQOYRg/n0PQOuYFY9ShLZn1iry85UsHvH5y2Z5tJ
         tDQi71qxsLN3LOEbpLNvPsheoNQa0gvrnSOImbxd6yC9LKVkLtCB7pMZgODkjd3fEaZZ
         RLVulHiwW6XckzdNl8PdMpAk8JGG7NL4MAmARiQfPaBYJbkW5WOAifoVaWZDQggfst8z
         LBggH0O3oC9rfhobtSYgqjRTl578Ro4BmXGCh8rkxw10DU6VRVkR75ePXpU4591ayxf4
         SXA6WnDbEGcbh/2DTNpAvJndFny58J/iGONzQlh24JSvU98a0ZDufTNwPJFvBDeNAg53
         I7cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NAPWBP7CuDFreLAWP9d0OtbbvgLd0xxTvpXtHQFwqyE=;
        b=ZY0bBvyhR/3lKYidSkvgCZmxSQrDy4MJEi28B9KIGGkt5ELr88HjxOhT7o7E6fZG1+
         Lo2jWNS8naysePraUaEbD+fo+cP455VxIG3BBR/O7Pdx5GFXBk58WkZsuVKue4LGiZQb
         IDVKI5qpHLihu6E7oKBdgktIgFqKS1Ei6cS70PrMMV6XdhxkCIZAiQaLviln+2wZ7EyT
         kBsEzq/sOvVtd5UD5/2KkbCRVgp+8bEuTlV5heVg9oFDfF5CHsI8x5QKU/3xvQLIwm23
         yp2LGimJ8pIH13n4GzsWLR4mHi2ZzWdqQJmzdEMuxY2A6xUgnStNK5KglgP2Qqk10+0G
         jWyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nj0nK9hM;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id w2si42713pgt.2.2019.12.18.01.08.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Dec 2019 01:08:58 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id w127so929872qkb.11
        for <kasan-dev@googlegroups.com>; Wed, 18 Dec 2019 01:08:58 -0800 (PST)
X-Received: by 2002:ae9:eb48:: with SMTP id b69mr1335544qkg.43.1576660137547;
 Wed, 18 Dec 2019 01:08:57 -0800 (PST)
MIME-Version: 1.0
References: <00000000000021cc1a0599f66f55@google.com>
In-Reply-To: <00000000000021cc1a0599f66f55@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 Dec 2019 10:08:45 +0100
Message-ID: <CACT4Y+Y0FXiGgsMt=k9d73bkQvW-NqyUoS=w6KXQ=28_ROz1YA@mail.gmail.com>
Subject: Re: BUG: soft lockup in sock_setsockopt
To: syzbot <syzbot+e7e13ce5d4ca294ca90a@syzkaller.appspotmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Daniel Axtens <dja@axtens.net>
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	LKML <linux-kernel@vger.kernel.org>, namit@vmware.com, 
	Peter Zijlstra <peterz@infradead.org>, syzkaller-bugs <syzkaller-bugs@googlegroups.com>, 
	Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nj0nK9hM;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, Dec 18, 2019 at 9:43 AM syzbot
<syzbot+e7e13ce5d4ca294ca90a@syzkaller.appspotmail.com> wrote:
>
> Hello,
>
> syzbot found the following crash on:
>
> HEAD commit:    9065e063 Merge branch 'x86-urgent-for-linus' of git://git...
> git tree:       upstream
> console output: https://syzkaller.appspot.com/x/log.txt?x=17185e99e00000
> kernel config:  https://syzkaller.appspot.com/x/.config?x=dcf10bf83926432a
> dashboard link: https://syzkaller.appspot.com/bug?extid=e7e13ce5d4ca294ca90a
> compiler:       gcc (GCC) 9.0.0 20181231 (experimental)
>
> Unfortunately, I don't have any reproducer for this crash yet.
>
> IMPORTANT: if you fix the bug, please add the following tag to the commit:
> Reported-by: syzbot+e7e13ce5d4ca294ca90a@syzkaller.appspotmail.com

+Daniel, kasan-dev,

This looks like another stall caused by KASAN+vmalloc. Now it has
reached upstream and this instance uses Apparmor rather than Smack.

> watchdog: BUG: soft lockup - CPU#0 stuck for 122s! [syz-executor.3:9634]
> Modules linked in:
> irq event stamp: 35786
> hardirqs last  enabled at (35785): [<ffffffff81006983>]
> trace_hardirqs_on_thunk+0x1a/0x1c arch/x86/entry/thunk_64.S:41
> hardirqs last disabled at (35786): [<ffffffff8100699f>]
> trace_hardirqs_off_thunk+0x1a/0x1c arch/x86/entry/thunk_64.S:42
> softirqs last  enabled at (5788): [<ffffffff880006cd>]
> __do_softirq+0x6cd/0x98c kernel/softirq.c:319
> softirqs last disabled at (5707): [<ffffffff81478ceb>] invoke_softirq
> kernel/softirq.c:373 [inline]
> softirqs last disabled at (5707): [<ffffffff81478ceb>] irq_exit+0x19b/0x1e0
> kernel/softirq.c:413
> CPU: 0 PID: 9634 Comm: syz-executor.3 Not tainted 5.5.0-rc2-syzkaller #0
> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS
> Google 01/01/2011
> RIP: 0010:__read_once_size include/linux/compiler.h:199 [inline]
> RIP: 0010:csd_lock_wait kernel/smp.c:109 [inline]
> RIP: 0010:smp_call_function_single+0x188/0x480 kernel/smp.c:311
> Code: 00 e8 6c 23 0b 00 48 8b 4c 24 08 48 8b 54 24 10 48 8d 74 24 40 8b 7c
> 24 1c e8 c4 f9 ff ff 41 89 c5 eb 07 e8 4a 23 0b 00 f3 90 <44> 8b 64 24 58
> 31 ff 41 83 e4 01 44 89 e6 e8 b5 24 0b 00 45 85 e4
> RSP: 0018:ffffc90004d3f480 EFLAGS: 00000246 ORIG_RAX: ffffffffffffff13
> RAX: 0000000000040000 RBX: 1ffff920009a7e94 RCX: ffffc90010442000
> RDX: 0000000000040000 RSI: ffffffff816a0856 RDI: 0000000000000005
> RBP: ffffc90004d3f550 R08: ffff88809e5161c0 R09: ffffed1015d27059
> R10: ffffed1015d27058 R11: ffff8880ae9382c7 R12: 0000000000000001
> R13: 0000000000000000 R14: 0000000000000001 R15: 0000000000000000
> FS:  00007f19610d6700(0000) GS:ffff8880ae800000(0000) knlGS:0000000000000000
> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> CR2: 00007fe53bcc09c0 CR3: 000000008ffc6000 CR4: 00000000001426f0
> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> Call Trace:
>   smp_call_function_many+0x7ba/0x940 kernel/smp.c:451
>   smp_call_function+0x42/0x90 kernel/smp.c:509
>   on_each_cpu+0x2f/0x1f0 kernel/smp.c:616
>   flush_tlb_kernel_range+0x19b/0x250 arch/x86/mm/tlb.c:839
>   kasan_release_vmalloc+0xb4/0xc0 mm/kasan/common.c:976
>   __purge_vmap_area_lazy+0xca5/0x1ef0 mm/vmalloc.c:1313
>   _vm_unmap_aliases mm/vmalloc.c:1730 [inline]
>   _vm_unmap_aliases+0x396/0x480 mm/vmalloc.c:1695
>   vm_unmap_aliases+0x19/0x20 mm/vmalloc.c:1753
>   change_page_attr_set_clr+0x22e/0x840 arch/x86/mm/pageattr.c:1709
>   change_page_attr_clear arch/x86/mm/pageattr.c:1766 [inline]
>   set_memory_ro+0x7b/0xa0 arch/x86/mm/pageattr.c:1899
>   bpf_jit_binary_lock_ro include/linux/filter.h:790 [inline]
>   bpf_int_jit_compile+0xebd/0x12ce arch/x86/net/bpf_jit_comp.c:1659
>   bpf_prog_select_runtime+0x4b9/0x850 kernel/bpf/core.c:1801
>   bpf_migrate_filter net/core/filter.c:1275 [inline]
>   bpf_prepare_filter net/core/filter.c:1323 [inline]
>   bpf_prepare_filter+0x977/0xd60 net/core/filter.c:1289
>   __get_filter+0x212/0x2c0 net/core/filter.c:1492
>   sk_attach_filter+0x1e/0xa0 net/core/filter.c:1507
>   sock_setsockopt+0x1f44/0x22b0 net/core/sock.c:999
>   __sys_setsockopt+0x440/0x4c0 net/socket.c:2113
>   __do_sys_setsockopt net/socket.c:2133 [inline]
>   __se_sys_setsockopt net/socket.c:2130 [inline]
>   __x64_sys_setsockopt+0xbe/0x150 net/socket.c:2130
>   do_syscall_64+0xfa/0x790 arch/x86/entry/common.c:294
>   entry_SYSCALL_64_after_hwframe+0x49/0xbe
> RIP: 0033:0x45a919
> Code: ad b6 fb ff c3 66 2e 0f 1f 84 00 00 00 00 00 66 90 48 89 f8 48 89 f7
> 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff
> ff 0f 83 7b b6 fb ff c3 66 2e 0f 1f 84 00 00 00 00
> RSP: 002b:00007f19610d5c78 EFLAGS: 00000246 ORIG_RAX: 0000000000000036
> RAX: ffffffffffffffda RBX: 0000000000000005 RCX: 000000000045a919
> RDX: 000000000000001a RSI: 0000000000000001 RDI: 000000000000000c
> RBP: 000000000075c070 R08: 0000000000000010 R09: 0000000000000000
> R10: 0000000020000480 R11: 0000000000000246 R12: 00007f19610d66d4
> R13: 00000000004c9e34 R14: 00000000004e1f78 R15: 00000000ffffffff
> Sending NMI from CPU 0 to CPUs 1:
> NMI backtrace for cpu 1
> CPU: 1 PID: 3231 Comm: kworker/1:3 Not tainted 5.5.0-rc2-syzkaller #0
> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS
> Google 01/01/2011
> Workqueue: rcu_gp process_srcu
> RIP: 0010:delay_tsc+0x33/0xc0 arch/x86/lib/delay.c:68
> Code: bf 01 00 00 00 41 55 41 54 53 e8 58 95 8b f9 e8 63 b4 cd fb 41 89 c5
> 0f 01 f9 66 90 48 c1 e2 20 48 09 c2 49 89 d4 eb 16 f3 90 <bf> 01 00 00 00
> e8 33 95 8b f9 e8 3e b4 cd fb 44 39 e8 75 36 0f 01
> RSP: 0018:ffffc9000898fbb0 EFLAGS: 00000286
> RAX: 0000000080000000 RBX: 000000c937e7f04b RCX: 0000000000000000
> RDX: 0000000000000001 RSI: ffffffff8392f013 RDI: 0000000000000001
> RBP: ffffc9000898fbd0 R08: ffff88809e1e2200 R09: 0000000000000040
> R10: 0000000000000040 R11: ffffffff89a4f487 R12: 000000c937e7c4ab
> R13: 0000000000000001 R14: 0000000000002ced R15: 0000000000000047
> FS:  0000000000000000(0000) GS:ffff8880ae900000(0000) knlGS:0000000000000000
> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> CR2: 00007fbb9d9c6000 CR3: 0000000094911000 CR4: 00000000001426e0
> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> Call Trace:
>   __delay arch/x86/lib/delay.c:161 [inline]
>   __const_udelay+0x59/0x80 arch/x86/lib/delay.c:175
>   try_check_zero+0x201/0x330 kernel/rcu/srcutree.c:705
>   srcu_advance_state kernel/rcu/srcutree.c:1142 [inline]
>   process_srcu+0x329/0xe10 kernel/rcu/srcutree.c:1237
>   process_one_work+0x9af/0x1740 kernel/workqueue.c:2264
>   worker_thread+0x98/0xe40 kernel/workqueue.c:2410
>   kthread+0x361/0x430 kernel/kthread.c:255
>   ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:352
>
>
> ---
> This bug is generated by a bot. It may contain errors.
> See https://goo.gl/tpsmEJ for more information about syzbot.
> syzbot engineers can be reached at syzkaller@googlegroups.com.
>
> syzbot will keep track of this bug report. See:
> https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
>
> --
> You received this message because you are subscribed to the Google Groups "syzkaller-bugs" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller-bugs+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller-bugs/00000000000021cc1a0599f66f55%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY0FXiGgsMt%3Dk9d73bkQvW-NqyUoS%3Dw6KXQ%3D28_ROz1YA%40mail.gmail.com.
