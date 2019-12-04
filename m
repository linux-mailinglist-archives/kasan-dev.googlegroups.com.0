Return-Path: <kasan-dev+bncBCMIZB7QWENRB77WT3XQKGQEDHMRYIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id AF5A4112D10
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Dec 2019 14:58:24 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id h190sf4257818ybg.5
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Dec 2019 05:58:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575467903; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kkkd3/qitvEglQk50NJUfEH/GZHuCYvuojUZr1U+ayLBrkw9QSGfvZHmhGtv9oqEbw
         cUgFl4PjGC1vZi5g8kiITwRCILsB2RphOx+OwOklhtjUIaSt52v8vm6la/GHaPBABiyB
         PsGGDpBSyCSFvkNJ8jR2IAuwtGnqC73o3c1uRVf4cyTv92NG5U/2itjfA6qbV2aTRDzd
         0RX7yDShirmXGS1YEwKm71kZIVzltNKmiaceRdO73tMC+4Pba8AgI/7MazLNINaa8UsB
         Bo+LmZ7RhtJfB55DM+8WXU9fq+/RkMcMA4OBDAKotFCllAmVExMSyvJrfJflyctFepMN
         VBew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4Cufil3pn7NQCW+61ax4TbBTIuDXMNA8p/fTzOzqBns=;
        b=u95sGcEEowq+HyarcuOcv16UGa+HJvWMGYuc+IqiwpvRpNxsynoh+uXfxvGwVR0cVm
         meu5OluqlB70AMb0XfJHChXjaHl7dMsdQKtMvGIJvdIrmVbIIjBvr5mdrXaHmGfuap4g
         LJuYutSOG0n8S75xjUvpi65rhjhfVEFcOvPyAefCLaHCmPl0DeiQhcchzB+ctqClJYZL
         34uGv3gWk6Q9GAPtHl7Hq+m3EyvlkZFqg+a0WbnknM8VJ5j4kc30HTVVAJEIoZMDJXiF
         mk5kYbw/LIch/MsUV8n3Zj9aXdqb/ZDY6kF9XlkTCGK8DsI7ihmj++EPp9sj8VCn+VqT
         I9VQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tJ6NRvsb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4Cufil3pn7NQCW+61ax4TbBTIuDXMNA8p/fTzOzqBns=;
        b=R4z75HzVa5yMNJwIkTRZHXykr8GxtYORKd51Z21VR1pHrB3sKeUjEns9aTwMM++Rg1
         0dZEjLGAqSbkH2rvzN3XVAbf4I0PhhOWqzCvqLhNsRvrP9l8mYiU8AXntHMB6XX95dHP
         PpE8Mu3bYizmAFcIH7zmYkqBCal4CW0wLCBc4RYn5t6pGqM3y0NAN8KlEksuCONBeBkr
         YM5CJUM9iuhwkU51fYPxnRi9KQimMvckveONmFkbEoqQvgjfRdpezhcGHEkA7qTn/SyX
         Qa6RUGosoZP3R5/d7VPlpMAGWKPHORm1sP4NNewmNoeQbWob1ptsVQVWXaRrJKiOKqFc
         QHow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4Cufil3pn7NQCW+61ax4TbBTIuDXMNA8p/fTzOzqBns=;
        b=lwqEjTlUTcsrntiiCun9iAFapR29q59jJEEye/EYpabjj13RSdinUOd9S/kkoEdFT/
         3RSJDLOJ1eVCiDq7zAPJdkdI/AdcKBlahMeEXUAZYBXfGKZydxkXlCNZF/xnxWNoHt3a
         xJ981o1ZO9g5Adb6f2cuXeHBMtvzSjYuFCL+RVg97kT7Xn3Sqgu90BUj0pbQvI430Egx
         NJr04eath0+/BTsO4DES2VdL/2ZBiQfFIRg8AtGWj40XRRgsvU+jIND9cf1+BdYXjcwa
         si03olT1zH7Ao/5sFfgnawzYag4tLfVf0GXvk/g6FZO+2yQMbxb2XdTaC4csykAF3rCB
         3HPQ==
X-Gm-Message-State: APjAAAXIuJpb8EIAiumlwouk9Rf2apmlUrayzxhq4cuQMGfR2qg8EARQ
	AUFFpxNxnYX9pMUg9FkaxzI=
X-Google-Smtp-Source: APXvYqyou8mQkJEKc1AFYPhne4vdHWA+jZRMMHx975yprM0F+XMES0wKDy1B+yqJymiBGz8uiK2QOQ==
X-Received: by 2002:a25:aaa4:: with SMTP id t33mr2422128ybi.274.1575467903339;
        Wed, 04 Dec 2019 05:58:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:481:: with SMTP id 123ls1041008ybe.1.gmail; Wed, 04 Dec
 2019 05:58:22 -0800 (PST)
X-Received: by 2002:a25:807:: with SMTP id 7mr2307450ybi.229.1575467902729;
        Wed, 04 Dec 2019 05:58:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575467902; cv=none;
        d=google.com; s=arc-20160816;
        b=eRhxASnkMecPGvCoSdJJ03XYvw1rbVjPTibbxMyB1e0MvbIXSQsA2SJiFbbA0lfq8z
         3QNGEyBOE0aAQmr4RYo41DfedOHTWlKAGoP5PCa0KZ4P5VJQLiX0CM0oXslxHrt2yRDs
         VpEd3jEzjJqJIBiEi7REmUJqkr3bUiu6mdGFGFuovmXXymQkdkSWQ1L8p/Rz0gm3u+KL
         XRFcYLCcMFJJawcCJu6wJu9Xigdn5eFNMeHclaYYuqByoARgHMZT0ilDCfTKtMBM7u59
         apk/FuF168gwBonL0XtNz+uiEtiujA5HGrWPj6bDZ4tAubjiOuGzlzO5iVVXs/nwYS9Y
         jqlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gQZRT9h5gGn+PRANbfIUGJFXwRG2sVqXF2x1gIv9kfs=;
        b=rkVcYP0hHsUGIfoAMg24CzMDu16836jY0odh6hMhRjTzJ8eJN/AnO2x6hRI9pq2bvL
         W3WV5Lnu8u/8rf2zQk6YibYaRldCVaPrwOz89K+xfPnFRpNKdnIcnzE2cdveopaX3TnS
         OcTlal26ASSh8vl7OeS1ZwKi5hQYubml/6ZzBWJzsYvX5cfStyK+XYnE1hkEb689xfNc
         7S+WfhP6u4qQCDfO9ub+RHkHuTb31EjJEqtxjC6WKe3Eiyvq2NI6rYoxfLeS+JFPeSzf
         3Wc+EutpY3yZuICLqc41hBCMiYSvtcOK95ZnxAWCqhZQlNuLKu1LubCVT3dT79Mn/rfv
         BiEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tJ6NRvsb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id v64si295385ywa.4.2019.12.04.05.58.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Dec 2019 05:58:22 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id b18so3055252qvo.8
        for <kasan-dev@googlegroups.com>; Wed, 04 Dec 2019 05:58:22 -0800 (PST)
X-Received: by 2002:a0c:b446:: with SMTP id e6mr2700026qvf.159.1575467901712;
 Wed, 04 Dec 2019 05:58:21 -0800 (PST)
MIME-Version: 1.0
References: <00000000000036decf0598c8762e@google.com> <CACT4Y+YVMUxeLcFMray9n0+cXbVibj5X347LZr8YgvjN5nC8pw@mail.gmail.com>
In-Reply-To: <CACT4Y+YVMUxeLcFMray9n0+cXbVibj5X347LZr8YgvjN5nC8pw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 Dec 2019 14:58:10 +0100
Message-ID: <CACT4Y+asdED7tYv462Ui2OhQVKXVUnC+=fumXR3qM1A4d6AvOQ@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=tJ6NRvsb;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42
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

On Tue, Dec 3, 2019 at 9:38 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Tue, Dec 3, 2019 at 9:27 AM syzbot
> <syzbot+de8d933e7d153aa0c1bb@syzkaller.appspotmail.com> wrote:
> >
> > Hello,
> >
> > syzbot found the following crash on:
> >
> > HEAD commit:    596cf45c Merge branch 'akpm' (patches from Andrew)
> > git tree:       upstream
> > console output: https://syzkaller.appspot.com/x/log.txt?x=15f11c2ae00000
> > kernel config:  https://syzkaller.appspot.com/x/.config?x=9bbcda576154a4b4
> > dashboard link: https://syzkaller.appspot.com/bug?extid=de8d933e7d153aa0c1bb
> > compiler:       clang version 9.0.0 (/home/glider/llvm/clang
> > 80fee25776c2fb61e74c1ecb1a523375c2500b69)
> >
> > Unfortunately, I don't have any reproducer for this crash yet.
> >
> > IMPORTANT: if you fix the bug, please add the following tag to the commit:
> > Reported-by: syzbot+de8d933e7d153aa0c1bb@syzkaller.appspotmail.com
>
> Something seriously broken in smack+kasan+vmap stacks, we now have 60
> rcu stalls all over the place and counting. This is one of the
> samples. I've duped 2 other samples to this one, you can see them on
> the dashboard:
> https://syzkaller.appspot.com/bug?extid=de8d933e7d153aa0c1bb
>
> I see 2 common this across all stalls:
> 1. They all happen on the instance that uses smack (which is now
> effectively dead), see smack instance here:
> https://syzkaller.appspot.com/upstream
> 2. They all contain this frame in the stack trace:
> free_thread_stack+0x168/0x590 kernel/fork.c:280
> The last commit that touches this file is "fork: support VMAP_STACK
> with KASAN_VMALLOC".
> That may be very likely the root cause. +Daniel

I've stopped smack syzbot instance b/c it produces infinite stream of
assorted crashes due to this.
Please ping syzkaller@googlegroups.com when this is fixed, I will
re-enable the instance.

> > rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
> >         (detected by 1, t=10502 jiffies, g=6629, q=331)
> > rcu: All QSes seen, last rcu_preempt kthread activity 10503
> > (4294953794-4294943291), jiffies_till_next_fqs=1, root ->qsmask 0x0
> > syz-executor.0  R  running task    24648  8293   8292 0x0000400a
> > Call Trace:
> >   <IRQ>
> >   sched_show_task+0x40f/0x560 kernel/sched/core.c:5954
> >   print_other_cpu_stall kernel/rcu/tree_stall.h:410 [inline]
> >   check_cpu_stall kernel/rcu/tree_stall.h:538 [inline]
> >   rcu_pending kernel/rcu/tree.c:2827 [inline]
> >   rcu_sched_clock_irq+0x1861/0x1ad0 kernel/rcu/tree.c:2271
> >   update_process_times+0x12d/0x180 kernel/time/timer.c:1726
> >   tick_sched_handle kernel/time/tick-sched.c:167 [inline]
> >   tick_sched_timer+0x263/0x420 kernel/time/tick-sched.c:1310
> >   __run_hrtimer kernel/time/hrtimer.c:1514 [inline]
> >   __hrtimer_run_queues+0x403/0x840 kernel/time/hrtimer.c:1576
> >   hrtimer_interrupt+0x38c/0xda0 kernel/time/hrtimer.c:1638
> >   local_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1110 [inline]
> >   smp_apic_timer_interrupt+0x109/0x280 arch/x86/kernel/apic/apic.c:1135
> >   apic_timer_interrupt+0xf/0x20 arch/x86/entry/entry_64.S:829
> >   </IRQ>
> > RIP: 0010:__read_once_size include/linux/compiler.h:199 [inline]
> > RIP: 0010:check_kcov_mode kernel/kcov.c:70 [inline]
> > RIP: 0010:__sanitizer_cov_trace_pc+0x1c/0x50 kernel/kcov.c:102
> > Code: cc 07 48 89 de e8 64 02 3b 00 5b 5d c3 cc 48 8b 04 24 65 48 8b 0c 25
> > c0 1d 02 00 65 8b 15 b8 81 8b 7e f7 c2 00 01 1f 00 75 2c <8b> 91 80 13 00
> > 00 83 fa 02 75 21 48 8b 91 88 13 00 00 48 8b 32 48
> > RSP: 0018:ffffc900021c7c28 EFLAGS: 00000246 ORIG_RAX: ffffffffffffff13
> > RAX: ffffffff81487433 RBX: 0000000000000000 RCX: ffff88809428a100
> > RDX: 0000000000000001 RSI: 00000000fffffffc RDI: ffffea0002479240
> > RBP: ffffc900021c7c50 R08: dffffc0000000000 R09: fffffbfff1287025
> > R10: fffffbfff1287025 R11: 0000000000000000 R12: dffffc0000000000
> > R13: dffffc0000000000 R14: 00000000fffffffc R15: ffff888091c57428
> >   free_thread_stack+0x168/0x590 kernel/fork.c:280
> >   release_task_stack kernel/fork.c:440 [inline]
> >   put_task_stack+0xa3/0x130 kernel/fork.c:451
> >   finish_task_switch+0x3f1/0x550 kernel/sched/core.c:3256
> >   context_switch kernel/sched/core.c:3388 [inline]
> >   __schedule+0x9a8/0xcc0 kernel/sched/core.c:4081
> >   preempt_schedule_common kernel/sched/core.c:4236 [inline]
> >   preempt_schedule+0xdb/0x120 kernel/sched/core.c:4261
> >   ___preempt_schedule+0x16/0x18 arch/x86/entry/thunk_64.S:50
> >   __raw_read_unlock include/linux/rwlock_api_smp.h:227 [inline]
> >   _raw_read_unlock+0x3a/0x40 kernel/locking/spinlock.c:255
> >   kill_something_info kernel/signal.c:1586 [inline]
> >   __do_sys_kill kernel/signal.c:3640 [inline]
> >   __se_sys_kill+0x5e9/0x6c0 kernel/signal.c:3634
> >   __x64_sys_kill+0x5b/0x70 kernel/signal.c:3634
> >   do_syscall_64+0xf7/0x1c0 arch/x86/entry/common.c:294
> >   entry_SYSCALL_64_after_hwframe+0x49/0xbe
> > RIP: 0033:0x422a17
> > Code: 44 00 00 48 c7 c2 d4 ff ff ff f7 d8 64 89 02 b8 ff ff ff ff c3 66 2e
> > 0f 1f 84 00 00 00 00 00 0f 1f 40 00 b8 3e 00 00 00 0f 05 <48> 3d 01 f0 ff
> > ff 0f 83 dd 32 ff ff c3 66 2e 0f 1f 84 00 00 00 00
> > RSP: 002b:00007fff38dca538 EFLAGS: 00000293 ORIG_RAX: 000000000000003e
> > RAX: ffffffffffffffda RBX: 0000000000000064 RCX: 0000000000422a17
> > RDX: 0000000000000bb8 RSI: 0000000000000009 RDI: 00000000fffffffe
> > RBP: 0000000000000002 R08: 0000000000000001 R09: 0000000001c62940
> > R10: 0000000000000000 R11: 0000000000000293 R12: 0000000000000008
> > R13: 00007fff38dca570 R14: 000000000000f0b6 R15: 00007fff38dca580
> > rcu: rcu_preempt kthread starved for 10533 jiffies! g6629 f0x2
> > RCU_GP_WAIT_FQS(5) ->state=0x0 ->cpu=0
> > rcu: RCU grace-period kthread stack dump:
> > rcu_preempt     R  running task    29032    10      2 0x80004008
> > Call Trace:
> >   context_switch kernel/sched/core.c:3388 [inline]
> >   __schedule+0x9a8/0xcc0 kernel/sched/core.c:4081
> >   schedule+0x181/0x210 kernel/sched/core.c:4155
> >   schedule_timeout+0x14f/0x240 kernel/time/timer.c:1895
> >   rcu_gp_fqs_loop kernel/rcu/tree.c:1661 [inline]
> >   rcu_gp_kthread+0xed8/0x1770 kernel/rcu/tree.c:1821
> >   kthread+0x332/0x350 kernel/kthread.c:255
> >   ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:352
> >
> >
> > ---
> > This bug is generated by a bot. It may contain errors.
> > See https://goo.gl/tpsmEJ for more information about syzbot.
> > syzbot engineers can be reached at syzkaller@googlegroups.com.
> >
> > syzbot will keep track of this bug report. See:
> > https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
> >
> > --
> > You received this message because you are subscribed to the Google Groups "syzkaller-bugs" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller-bugs+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller-bugs/00000000000036decf0598c8762e%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BasdED7tYv462Ui2OhQVKXVUnC%2B%3DfumXR3qM1A4d6AvOQ%40mail.gmail.com.
