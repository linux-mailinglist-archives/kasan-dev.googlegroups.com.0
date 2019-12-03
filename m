Return-Path: <kasan-dev+bncBCMIZB7QWENRBC56TDXQKGQEDG5VCLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C05A10F9FB
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Dec 2019 09:38:37 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id k12sf30346plt.3
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Dec 2019 00:38:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575362315; cv=pass;
        d=google.com; s=arc-20160816;
        b=uRn5Jyen4+AKyUxjjgIcjTJBNfnF05Ub6Wjth/gTi/1Y+5laFo7rLztzFUEPBu631a
         vamQrDgXu7uvq0IkLBcAjWwYTRQrUPRRx68wDB32at4bjDAwA/NSGMtP1WNzWPWl24YI
         9o6HwVZd676nZuAO8ide7hpXeIVc49fXGCDUyD4I5ehb8/yoepx8dyoCoPAerwyBjJMF
         k8OH+zSray3sMDFgZ/w0NkMUUxV9uzkPep2XhcByMdi9NPR7kfZVvXoHHNc420FenpTO
         M5v8BxSEoy0NdBtWei9k2lAn7Srrd41fj+pyv7jCmXb03ShIFQAv4ishFy07SxvimVCN
         n+JQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wxEkSp+gScUpanqtwNdJdypE3p1ntWUuQ5HS0TnqSnA=;
        b=Hk9jVVAD3SJw3naQ53RLrYqPalFK8AVJdza9G9Dz291M0iCdTr+SRJi4AjoBcyugqd
         QYgxDhDS4Omw1GbMdzwnwQZH70H8KpFa8HjFMPqOhiqUgq1hD4wstWc9etjVM8UQwPaa
         GX8g59zUqgeL+341aomeMcoAWwUnpMxqmSh++GiHw0z5uaSDRMf1JGMoXmsdNam/a41S
         hOf7HT5MrME0MlTK8RFV/fNWPe+NcsEr1chVEV4zMPQnxIxk8PFw5XFcyVXKjlxvtRrf
         ohw0cuD7IbYHLTF4VrO/3fVTnETpBMifYWb6oXX+7Xs89i88tcQ+ZxNagDMZe+cfYm0K
         Nh1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=khAANywf;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wxEkSp+gScUpanqtwNdJdypE3p1ntWUuQ5HS0TnqSnA=;
        b=RnWJZ3v8wbBAXaWjy2EZ/jeLTs55Q4q4ItCKIYINoA7G2MNxJL7gOYdDZKX8bxnkSE
         /WTwL/DSiluiTXkDd7hQEC/6DxeKqckn1Sxi3Uc1z721WRwhJTNTHWNsgISTlIaUqbGM
         MdOLLLzUUijQnFjb4mLyPkRY3oJ9kf14dhuVlFUwD6ca28NciOcHWT5Si0J3PT4ew2lC
         JijmvSqxXfQpg8YTUmVqBrh+39vg4aQc8rDaz9VfD0TB0ejkyiahxjGdD8BDiWubbJwS
         ldEFVCUXlRTPPYoOQ0IP3KI3+jsQ7fTwk16ZwQPMumgos/UzfTSFACyqNFSOkBggsMyy
         Gl4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wxEkSp+gScUpanqtwNdJdypE3p1ntWUuQ5HS0TnqSnA=;
        b=Sf46mgxgwWJj+Kb3JzWJr9xszLtQxMVp7Jo7ozRzBdBvPsl/NVauRlXIvulSdIYkf4
         gANKxT45u5gM2x0wPmDJjaFt5/us62FSYuxK1oj7OFXIW3FrfK0OHlY8+kh06PvEGyFp
         VfsBV2+s1a+xbUuhJdwRLqQji9hwFS347ZgJeWuoWUbqa+xOPT0XqOygJo616A7YKlPJ
         tC8kqt18prfdwQCjkhPPklA0AAoGhI2L78uUbn8mUdB3KEfeYQOIb8bWoASJMokoVIpV
         w/m9W7aCgThJOy6IdPJMpTBv8M169nUy86lH7yg3LGtTQgQOUyailBaE3AjzEvWdVzDH
         EJJw==
X-Gm-Message-State: APjAAAXh4N4vNCxMN7huOk+VDfI5N4BlZiYaFqVclS1frWjFUzqNYPoP
	QreN+Q3tftV3EL/BbZbWQQg=
X-Google-Smtp-Source: APXvYqxlc7L2K6diOf0Bfxpv50tq+qN3Q9DGmyzEXPb5WoGQjsi3UwHkMqY9K2qLLhPmhEMA81GzmA==
X-Received: by 2002:a63:e115:: with SMTP id z21mr4068622pgh.441.1575362315586;
        Tue, 03 Dec 2019 00:38:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:fc0c:: with SMTP id j12ls619741pgi.15.gmail; Tue, 03 Dec
 2019 00:38:35 -0800 (PST)
X-Received: by 2002:a63:e84d:: with SMTP id a13mr4360981pgk.274.1575362315050;
        Tue, 03 Dec 2019 00:38:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575362315; cv=none;
        d=google.com; s=arc-20160816;
        b=FCABcMOXz32D9epL/BIecBNz+PiYUv0l6/5IXAmTC+ht7CEvpbusqR4WA9AOBg/7Xb
         yD0b+1zPHgx5ca5yfhKBVYB4mlHq1iXHX/SOSrDxxPv+1fD9v19sdU7YH1Ot9byvxNaG
         Nw0BIZTbVIbXpUsu2XaA+fLYvm+FMO7f8MFadhI1q8Ghs8mwhpBPqtXbT9eYTlGgRzhH
         5PePnvP/RoTzvsIaHxhuqsml+PeBG6HSdL7fKX+6Jqv5LYm4/CncdLGRS9sog+wuU4jt
         ENzYvtuoIgY0krJ9xi7Yz9Ijd4LOGmoSE/RIaeFT7T+l1FxKMSxfQcxyDrLH98Fkzox2
         dvlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=o7aLt1oUIvQVBX/J6Kkxyz9cvB9MeKi1aQENFI9rur8=;
        b=vbue7JIQxmAasdEzvBBNvpYJ8mcJJhlkqDvinrAsuPjrtUw2re3S2DfWDwcjSEkGlZ
         HB+k1mjzWdZsfAIrj/IEd6ZKAiahA7B7/NldreygcAFePD8R0Ae/o+STUyIiq1LGpggc
         GXgMxfKrLVtzD2m+AAfuu21dp9+YuWMCUeRuwJlQQJ8pd/lJwh3PMoC7jcQ7frtlDb0j
         c5ySRRqO+aib40x8uMNtwOdTO+G/MVCp0mgl2gA0imfVuTdb+rd4KIYrS+6LuGOJ9FXN
         JH5eR6rXI2l29j0TZ0sep2D8uzGT6EZ0uktoD9hjDvge+JO47Fwf8+6gtBAPoXMNoe9/
         V+LQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=khAANywf;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id n2si198300pgq.0.2019.12.03.00.38.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Dec 2019 00:38:35 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id v19so2662428qkv.3
        for <kasan-dev@googlegroups.com>; Tue, 03 Dec 2019 00:38:34 -0800 (PST)
X-Received: by 2002:a37:4782:: with SMTP id u124mr3999254qka.8.1575362313699;
 Tue, 03 Dec 2019 00:38:33 -0800 (PST)
MIME-Version: 1.0
References: <00000000000036decf0598c8762e@google.com>
In-Reply-To: <00000000000036decf0598c8762e@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 3 Dec 2019 09:38:22 +0100
Message-ID: <CACT4Y+YVMUxeLcFMray9n0+cXbVibj5X347LZr8YgvjN5nC8pw@mail.gmail.com>
Subject: Re: INFO: rcu detected stall in sys_kill
To: syzbot <syzbot+de8d933e7d153aa0c1bb@syzkaller.appspotmail.com>, 
	Casey Schaufler <casey@schaufler-ca.com>, 
	linux-security-module <linux-security-module@vger.kernel.org>, Daniel Axtens <dja@axtens.net>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, kasan-dev <kasan-dev@googlegroups.com>
Cc: Andrea Arcangeli <aarcange@redhat.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christian Brauner <christian@brauner.io>, christian@kellner.me, cyphar@cyphar.com, 
	"Reshetova, Elena" <elena.reshetova@intel.com>, Jason Gunthorpe <jgg@ziepe.ca>, 
	Kees Cook <keescook@chromium.org>, ldv@altlinux.org, 
	LKML <linux-kernel@vger.kernel.org>, Andy Lutomirski <luto@amacapital.net>, 
	Ingo Molnar <mingo@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Al Viro <viro@zeniv.linux.org.uk>, Will Drewry <wad@chromium.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=khAANywf;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
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

On Tue, Dec 3, 2019 at 9:27 AM syzbot
<syzbot+de8d933e7d153aa0c1bb@syzkaller.appspotmail.com> wrote:
>
> Hello,
>
> syzbot found the following crash on:
>
> HEAD commit:    596cf45c Merge branch 'akpm' (patches from Andrew)
> git tree:       upstream
> console output: https://syzkaller.appspot.com/x/log.txt?x=15f11c2ae00000
> kernel config:  https://syzkaller.appspot.com/x/.config?x=9bbcda576154a4b4
> dashboard link: https://syzkaller.appspot.com/bug?extid=de8d933e7d153aa0c1bb
> compiler:       clang version 9.0.0 (/home/glider/llvm/clang
> 80fee25776c2fb61e74c1ecb1a523375c2500b69)
>
> Unfortunately, I don't have any reproducer for this crash yet.
>
> IMPORTANT: if you fix the bug, please add the following tag to the commit:
> Reported-by: syzbot+de8d933e7d153aa0c1bb@syzkaller.appspotmail.com

Something seriously broken in smack+kasan+vmap stacks, we now have 60
rcu stalls all over the place and counting. This is one of the
samples. I've duped 2 other samples to this one, you can see them on
the dashboard:
https://syzkaller.appspot.com/bug?extid=de8d933e7d153aa0c1bb

I see 2 common this across all stalls:
1. They all happen on the instance that uses smack (which is now
effectively dead), see smack instance here:
https://syzkaller.appspot.com/upstream
2. They all contain this frame in the stack trace:
free_thread_stack+0x168/0x590 kernel/fork.c:280
The last commit that touches this file is "fork: support VMAP_STACK
with KASAN_VMALLOC".
That may be very likely the root cause. +Daniel


> rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
>         (detected by 1, t=10502 jiffies, g=6629, q=331)
> rcu: All QSes seen, last rcu_preempt kthread activity 10503
> (4294953794-4294943291), jiffies_till_next_fqs=1, root ->qsmask 0x0
> syz-executor.0  R  running task    24648  8293   8292 0x0000400a
> Call Trace:
>   <IRQ>
>   sched_show_task+0x40f/0x560 kernel/sched/core.c:5954
>   print_other_cpu_stall kernel/rcu/tree_stall.h:410 [inline]
>   check_cpu_stall kernel/rcu/tree_stall.h:538 [inline]
>   rcu_pending kernel/rcu/tree.c:2827 [inline]
>   rcu_sched_clock_irq+0x1861/0x1ad0 kernel/rcu/tree.c:2271
>   update_process_times+0x12d/0x180 kernel/time/timer.c:1726
>   tick_sched_handle kernel/time/tick-sched.c:167 [inline]
>   tick_sched_timer+0x263/0x420 kernel/time/tick-sched.c:1310
>   __run_hrtimer kernel/time/hrtimer.c:1514 [inline]
>   __hrtimer_run_queues+0x403/0x840 kernel/time/hrtimer.c:1576
>   hrtimer_interrupt+0x38c/0xda0 kernel/time/hrtimer.c:1638
>   local_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1110 [inline]
>   smp_apic_timer_interrupt+0x109/0x280 arch/x86/kernel/apic/apic.c:1135
>   apic_timer_interrupt+0xf/0x20 arch/x86/entry/entry_64.S:829
>   </IRQ>
> RIP: 0010:__read_once_size include/linux/compiler.h:199 [inline]
> RIP: 0010:check_kcov_mode kernel/kcov.c:70 [inline]
> RIP: 0010:__sanitizer_cov_trace_pc+0x1c/0x50 kernel/kcov.c:102
> Code: cc 07 48 89 de e8 64 02 3b 00 5b 5d c3 cc 48 8b 04 24 65 48 8b 0c 25
> c0 1d 02 00 65 8b 15 b8 81 8b 7e f7 c2 00 01 1f 00 75 2c <8b> 91 80 13 00
> 00 83 fa 02 75 21 48 8b 91 88 13 00 00 48 8b 32 48
> RSP: 0018:ffffc900021c7c28 EFLAGS: 00000246 ORIG_RAX: ffffffffffffff13
> RAX: ffffffff81487433 RBX: 0000000000000000 RCX: ffff88809428a100
> RDX: 0000000000000001 RSI: 00000000fffffffc RDI: ffffea0002479240
> RBP: ffffc900021c7c50 R08: dffffc0000000000 R09: fffffbfff1287025
> R10: fffffbfff1287025 R11: 0000000000000000 R12: dffffc0000000000
> R13: dffffc0000000000 R14: 00000000fffffffc R15: ffff888091c57428
>   free_thread_stack+0x168/0x590 kernel/fork.c:280
>   release_task_stack kernel/fork.c:440 [inline]
>   put_task_stack+0xa3/0x130 kernel/fork.c:451
>   finish_task_switch+0x3f1/0x550 kernel/sched/core.c:3256
>   context_switch kernel/sched/core.c:3388 [inline]
>   __schedule+0x9a8/0xcc0 kernel/sched/core.c:4081
>   preempt_schedule_common kernel/sched/core.c:4236 [inline]
>   preempt_schedule+0xdb/0x120 kernel/sched/core.c:4261
>   ___preempt_schedule+0x16/0x18 arch/x86/entry/thunk_64.S:50
>   __raw_read_unlock include/linux/rwlock_api_smp.h:227 [inline]
>   _raw_read_unlock+0x3a/0x40 kernel/locking/spinlock.c:255
>   kill_something_info kernel/signal.c:1586 [inline]
>   __do_sys_kill kernel/signal.c:3640 [inline]
>   __se_sys_kill+0x5e9/0x6c0 kernel/signal.c:3634
>   __x64_sys_kill+0x5b/0x70 kernel/signal.c:3634
>   do_syscall_64+0xf7/0x1c0 arch/x86/entry/common.c:294
>   entry_SYSCALL_64_after_hwframe+0x49/0xbe
> RIP: 0033:0x422a17
> Code: 44 00 00 48 c7 c2 d4 ff ff ff f7 d8 64 89 02 b8 ff ff ff ff c3 66 2e
> 0f 1f 84 00 00 00 00 00 0f 1f 40 00 b8 3e 00 00 00 0f 05 <48> 3d 01 f0 ff
> ff 0f 83 dd 32 ff ff c3 66 2e 0f 1f 84 00 00 00 00
> RSP: 002b:00007fff38dca538 EFLAGS: 00000293 ORIG_RAX: 000000000000003e
> RAX: ffffffffffffffda RBX: 0000000000000064 RCX: 0000000000422a17
> RDX: 0000000000000bb8 RSI: 0000000000000009 RDI: 00000000fffffffe
> RBP: 0000000000000002 R08: 0000000000000001 R09: 0000000001c62940
> R10: 0000000000000000 R11: 0000000000000293 R12: 0000000000000008
> R13: 00007fff38dca570 R14: 000000000000f0b6 R15: 00007fff38dca580
> rcu: rcu_preempt kthread starved for 10533 jiffies! g6629 f0x2
> RCU_GP_WAIT_FQS(5) ->state=0x0 ->cpu=0
> rcu: RCU grace-period kthread stack dump:
> rcu_preempt     R  running task    29032    10      2 0x80004008
> Call Trace:
>   context_switch kernel/sched/core.c:3388 [inline]
>   __schedule+0x9a8/0xcc0 kernel/sched/core.c:4081
>   schedule+0x181/0x210 kernel/sched/core.c:4155
>   schedule_timeout+0x14f/0x240 kernel/time/timer.c:1895
>   rcu_gp_fqs_loop kernel/rcu/tree.c:1661 [inline]
>   rcu_gp_kthread+0xed8/0x1770 kernel/rcu/tree.c:1821
>   kthread+0x332/0x350 kernel/kthread.c:255
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
> To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller-bugs/00000000000036decf0598c8762e%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYVMUxeLcFMray9n0%2BcXbVibj5X347LZr8YgvjN5nC8pw%40mail.gmail.com.
