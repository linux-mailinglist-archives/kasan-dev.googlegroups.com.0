Return-Path: <kasan-dev+bncBCMIZB7QWENRBIV4TDXQKGQEJCDHM7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id B06C010F9F0
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Dec 2019 09:34:43 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id d12sf1672185qvj.16
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Dec 2019 00:34:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575362082; cv=pass;
        d=google.com; s=arc-20160816;
        b=pu0rRH/gh6a7bqxs6PZHjuG5dL0oq1Zu/VU6U8MZ6tBqQQloYrbDO5goWjcprIgDAm
         pcP2vBCm3kY6cAFyW+a/COTJeGxaOn6+C2QdOwcKyq+OmaYFKSq9+B8lpGVHH6VYcq9Y
         TFxrmuhX7sZHGTlIY0qLZ03AdyWB1poatFpCVyJkh8p6KBFtk038E2IC3tb3l4glJoAm
         UIxHg2epjapOYszHvORuzgHrUQuifYw0kKxf7/38KfqnzHM9MnC7p72B8fW33/YwYmua
         GkCAZhdgudKEPYp5tRligqFgxPm07OzWEBSBak7h3ixfOmL2sZe61HnL5dXYhZ7+HPpD
         X0qQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hS7oirkWgTYWz0q5Ui3orGNOCUOhZoFCYIKCsRaQ88k=;
        b=jg4eOwKu4T5saFnInS1xfRV1MziPttK7E4qw7mRAtvruTEymdPWYN63mh/pYT718wv
         aCOkEwxidvuwYrZlsbkkg4FOdUsJmNUPbaa4BL+Fr3Cjqz5PoO+ybWqlGAFRBDgK8K3x
         xDSb7V/q0si5cahIVzZNsn0iU2CRY1RrB+hwCBWod2hNxP23mmyV52SfBbFDamdy1FkR
         WbRXEUgUrkc5nkeaJwH71MwFpvZ9FbGIkjvJPO0NQ0EtIIHfJwDLQ0eCemRs6vJWNcc2
         Kv7wGRubPsr4KOmb3mwvvrxUBajHUh/m64mfLC7b1sf4QvTltcU+BKd5z2Z8gfbGL/6Q
         D9QA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KRN+1znG;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hS7oirkWgTYWz0q5Ui3orGNOCUOhZoFCYIKCsRaQ88k=;
        b=iq6Za/hO2gNUSwmQw5j0NbOfW8QazY4+S2+rDIL0wP/nEH69yLo8GOFzvICu2skMSU
         2Rrih5aiK3ticmT0qWo/s1b4/wW7BuHjGcQI7Q/NdH3/v/dh3nfl3SATAsUyJJ7/ARse
         qr3KT0K33IYjkAbHNnHEeatjYeY7E7zcqU0RogLp+x9ayZiAv4M51c75sTUR8gPAnj4Q
         nGZ9hc1UJPd7NYRaF6SH7hkrAfnWHnmEx9DRSMtC0OgtM5gZ7xy4u7x+4eKlbKaf86uy
         i4irXs0AEy1PXxiuarUUcwq8jclmZmlE4ND+JExbbWVYjaQT3iB1BDt0MmGStjjVQwPm
         SNiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hS7oirkWgTYWz0q5Ui3orGNOCUOhZoFCYIKCsRaQ88k=;
        b=X7wKCGFeuPcuDmjH8rsj9nQRnyWOhkXzNv6DyWTsLve+wOjYMNC6ZfdHCoLXsMqzFh
         Zj605ZSNUqOzC3lI1Q0NnZ4TDqnFiOMTQiaEqDaBTKXcFJf0NtODebVAQdFmfe6VqBeR
         eebd7onbyq2uxefC6WAaCnWGRjvTi+NPX4ZxF8NtxPBDfr/tePqEg35gVP9EjULVy9Tp
         8c1/Gdqp7QlxLxQ1KyZ4KXOBlKQOIryDSxQTw0gvBIdiQ3pOG9Ep9/iTSr4wCR4oTLQl
         cz/g6TODOXvjrfuEcJjBn/PXNEBdYK7xNM5gt65K6nLvroUy5ZaYUUWHf6/3o5qX/04Z
         utqA==
X-Gm-Message-State: APjAAAXiLtJ9Cwba5PRX+kMLZ8yb2cOJOi9cZ7i3H8EDeHExRAwOG/5e
	Fc3kqzs1jx76HmPscWGtOOs=
X-Google-Smtp-Source: APXvYqwbsfl/Tgl6Vu4fyRQoWwn4Y9W7cCF75mIWv2Hb2ACVJTDpxxSSBJ168DrzdT1VZBWhB64lOQ==
X-Received: by 2002:a37:6694:: with SMTP id a142mr3883370qkc.274.1575362082682;
        Tue, 03 Dec 2019 00:34:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:6682:: with SMTP id a124ls934837qkc.15.gmail; Tue, 03
 Dec 2019 00:34:42 -0800 (PST)
X-Received: by 2002:a37:7487:: with SMTP id p129mr3960317qkc.296.1575362082245;
        Tue, 03 Dec 2019 00:34:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575362082; cv=none;
        d=google.com; s=arc-20160816;
        b=rUfmEd3V9Aw3/JGRQRFkItToWKvaF7BT6PY6yCATWYXGHsaHzYfjABbyypU0Lxu8G3
         3bqWMnBhB+fs+ay6thi+i2R8rdGGOVrkx9TsiIrKmnhTFG8PDKtv3NMlobRSgd6f2vbW
         volTbtASMHB+EYz9og6ruJDS7zxMWdngJSG9wdGiiwwKEONblNCqEB50Tf9rz4N2708G
         gDbPfL+DvSbv1Ext1Mc5rtkk9qmWtrxnIq+wF7EjcMkLiELp39+CdndbjDkOQUzC5eWs
         WkOjyb3SB9Fez6DfD5DDKbuFIT9TgvoX4mAPKuUy7lVJ5bfxpXHzMx6QXRoWXPodqdPu
         Y6ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WE8c4qrvYO1bS4Cz4rfqeIP68iNlGE5erawwEVWjZZA=;
        b=X3eeX3cuI0yPRxpbeTNrH1dhInmBEPZidPRz73MflBH2SUWFAOyV6s3zxnnTTpvpJ2
         wjGjyS6hzbNvotvsrilzXIzldqC4S5IFR+gHpHRqs2ds6m8CLB4Ma//kBxxtqxaDYjmK
         z+0MQXn5wf3/IM1Y2g7kjt4hqXdUSDHVnF/INV57ateZjE8IQcGu8E/E8KNvtiFq7GDm
         fLxf9Z2tZe76VdilvAWj5NjNIiXUEuweAlSrNdyQKJK8EjdcUhJ+raMS/Qfr86RRbI9l
         Id/k/vCE597KjDgGLTQzqAKswE0UAJhRmPzP0bBehPUf5877293pfErCvQpEoeUCCIzg
         4Vkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KRN+1znG;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id n22si103450qkg.2.2019.12.03.00.34.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Dec 2019 00:34:42 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id c124so2677381qkg.0
        for <kasan-dev@googlegroups.com>; Tue, 03 Dec 2019 00:34:42 -0800 (PST)
X-Received: by 2002:a37:bdc3:: with SMTP id n186mr3583700qkf.407.1575362081539;
 Tue, 03 Dec 2019 00:34:41 -0800 (PST)
MIME-Version: 1.0
References: <000000000000d2a8cc0598c8798f@google.com>
In-Reply-To: <000000000000d2a8cc0598c8798f@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 3 Dec 2019 09:34:30 +0100
Message-ID: <CACT4Y+YVVK6sO6nE9wwYSgCjaZKR-h2HSJ120CFBimjjxZVJgQ@mail.gmail.com>
Subject: Re: INFO: rcu detected stall in pipe_read
To: syzbot <syzbot+7047406d4ba783c8eb7b@syzkaller.appspotmail.com>, 
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
 header.i=@google.com header.s=20161025 header.b=KRN+1znG;       spf=pass
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

On Tue, Dec 3, 2019 at 9:28 AM syzbot
<syzbot+7047406d4ba783c8eb7b@syzkaller.appspotmail.com> wrote:
>
> Hello,
>
> syzbot found the following crash on:
>
> HEAD commit:    596cf45c Merge branch 'akpm' (patches from Andrew)
> git tree:       upstream
> console output: https://syzkaller.appspot.com/x/log.txt?x=17b1af36e00000
> kernel config:  https://syzkaller.appspot.com/x/.config?x=9bbcda576154a4b4
> dashboard link: https://syzkaller.appspot.com/bug?extid=7047406d4ba783c8eb7b
> compiler:       clang version 9.0.0 (/home/glider/llvm/clang
> 80fee25776c2fb61e74c1ecb1a523375c2500b69)
>
> Unfortunately, I don't have any reproducer for this crash yet.
>
> IMPORTANT: if you fix the bug, please add the following tag to the commit:
> Reported-by: syzbot+7047406d4ba783c8eb7b@syzkaller.appspotmail.com

Something seriously broke in smack+kasan+vmap stacks, we now have 60
rcu stalls all over the place and counting. This is one of the
samples. Let's dup all of them to a single one and continue the
discussion there:

#syz dup: INFO: rcu detected stall in sys_kill

> rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
>         (detected by 0, t=10502 jiffies, g=5977, q=61)
> rcu: All QSes seen, last rcu_preempt kthread activity 10503
> (4294953644-4294943141), jiffies_till_next_fqs=1, root ->qsmask 0x0
> syz-executor.0  R  running task    24296  8125   8124 0x0000400a
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
> RIP: 0010:mod_memcg_page_state+0x2b/0x190 include/linux/memcontrol.h:653
> Code: 48 89 e5 41 57 41 56 41 54 53 41 89 f6 48 89 fb e8 da 28 2e 00 48 83
> c3 38 48 89 d8 48 c1 e8 03 49 bc 00 00 00 00 00 fc ff df <42> 80 3c 20 00
> 74 08 48 89 df e8 b6 9f 69 00 48 8b 1b 48 85 db 0f
> RSP: 0018:ffffc90001f27998 EFLAGS: 00000a02 ORIG_RAX: ffffffffffffff13
> RAX: 1ffffd40005452bf RBX: ffffea0002a295f8 RCX: ffff88808f094580
> RDX: 0000000000000000 RSI: 00000000fffffffc RDI: ffffea0002a295c0
> RBP: ffffc90001f279b8 R08: dffffc0000000000 R09: fffffbfff1287025
> R10: fffffbfff1287025 R11: 0000000000000000 R12: dffffc0000000000
> R13: dffffc0000000000 R14: 00000000fffffffc R15: ffff8880a8a6f4a8
>   free_thread_stack+0x168/0x590 kernel/fork.c:280
>   release_task_stack kernel/fork.c:440 [inline]
>   put_task_stack+0xa3/0x130 kernel/fork.c:451
>   finish_task_switch+0x3f1/0x550 kernel/sched/core.c:3256
>   context_switch kernel/sched/core.c:3388 [inline]
>   __schedule+0x9a8/0xcc0 kernel/sched/core.c:4081
>   preempt_schedule_common kernel/sched/core.c:4236 [inline]
>   preempt_schedule+0xdb/0x120 kernel/sched/core.c:4261
>   ___preempt_schedule+0x16/0x18 arch/x86/entry/thunk_64.S:50
>   __raw_spin_unlock_irqrestore include/linux/spinlock_api_smp.h:161 [inline]
>   _raw_spin_unlock_irqrestore+0xcc/0xe0 kernel/locking/spinlock.c:191
>   spin_unlock_irqrestore include/linux/spinlock.h:393 [inline]
>   __wake_up_common_lock kernel/sched/wait.c:125 [inline]
>   __wake_up+0xe1/0x150 kernel/sched/wait.c:142
>   pipe_read+0x8e1/0x9e0 fs/pipe.c:374
>   call_read_iter include/linux/fs.h:1896 [inline]
>   new_sync_read fs/read_write.c:414 [inline]
>   __vfs_read+0x59e/0x730 fs/read_write.c:427
>   vfs_read+0x1dd/0x420 fs/read_write.c:461
>   ksys_read+0x117/0x220 fs/read_write.c:587
>   __do_sys_read fs/read_write.c:597 [inline]
>   __se_sys_read fs/read_write.c:595 [inline]
>   __x64_sys_read+0x7b/0x90 fs/read_write.c:595
>   do_syscall_64+0xf7/0x1c0 arch/x86/entry/common.c:294
>   entry_SYSCALL_64_after_hwframe+0x49/0xbe
> RIP: 0033:0x414190
> Code: 01 f0 ff ff 0f 83 90 1b 00 00 c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f
> 44 00 00 83 3d dd 42 66 00 00 75 14 b8 00 00 00 00 0f 05 <48> 3d 01 f0 ff
> ff 0f 83 64 1b 00 00 c3 48 83 ec 08 e8 6a fc ff ff
> RSP: 002b:00007fff84902588 EFLAGS: 00000246 ORIG_RAX: 0000000000000000
> RAX: ffffffffffffffda RBX: 0000000000000003 RCX: 0000000000414190
> RDX: 0000000000000038 RSI: 0000000000758040 RDI: 00000000000000f9
> RBP: 0000000000000002 R08: 00000000000003b8 R09: 0000000000004000
> R10: 0000000000717660 R11: 0000000000000246 R12: 0000000000000000
> R13: 00007fff849025c0 R14: 000000000000e9c4 R15: 00007fff849025d0
> rcu: rcu_preempt kthread starved for 10534 jiffies! g5977 f0x2
> RCU_GP_WAIT_FQS(5) ->state=0x0 ->cpu=0
> rcu: RCU grace-period kthread stack dump:
> rcu_preempt     R  running task    29104    10      2 0x80004000
> Call Trace:
>   context_switch kernel/sched/core.c:3385 [inline]
>   __schedule+0x9a0/0xcc0 kernel/sched/core.c:4081
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
> To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller-bugs/000000000000d2a8cc0598c8798f%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYVVK6sO6nE9wwYSgCjaZKR-h2HSJ120CFBimjjxZVJgQ%40mail.gmail.com.
