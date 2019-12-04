Return-Path: <kasan-dev+bncBDQ27FVWWUFRB4EEUHXQKGQETK62HZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C0A7113845
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Dec 2019 00:34:10 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id r127sf590092pfc.11
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Dec 2019 15:34:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575502449; cv=pass;
        d=google.com; s=arc-20160816;
        b=pkV+kAqIb9ugi6G3wGAFWHk7coSIQ4cYpoIh14lb/BIw2y5vOL3/kXO9OBZQUP4eJx
         2T6rkg/t/6XiosVQXfOaqP64NiLcQ/raQ35srNv/rAs1KEptvXypnQoV9qF2AyoSergl
         D8NVM2Q7fmWfyfgIxxrB4POLGJS923Y+V0W7B5aEAp2a6+tHz2tZufI+NY5NRObhqxLj
         Gs8a5NCDrEg0Ftozx2rBZ8tBTvV3ptVUV9yi6k27bxlpYKXw4uFf0u8YMWrHOXHGXed+
         LzyH85EzA3sEGXL1E6TlJ0JcPOLJVV+aDwbDbs805CIY9B9onTaNowR9/K2DHMZJWqmh
         HsBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=f2CVbo4iFRgkm6egBoV0zn8ROn3YXbfZe1nM7EvzU4M=;
        b=TpYxn5bY7hmH/bpvNEeZUOSynUC8bp/9hF/WaO0KWNDVujpz2hNshhRBgL6ST8m2ix
         gPKb18OBsJ1XgwS8cBit7TWJWQIh3BaBMN0AFD548hu3TrwVLoJVMUxYnw8S6llLhD4u
         XPP4jfyqoJ9NI9upComBzhrU/xQjDRGr8sV4quMHQxJaafULu3welHMWmM7eY8Qn+/Rn
         XDcs4A9miE5WXrZxj5MOsBY9fKtDzl/bgTwgua9Vdqrv6s3lW/kvV7tAM8RvHHwbM8Jk
         9yj6K00LJCtxKMHKKXuCJ4uZsehwWM6f512JDPmlFQf5JEVKlmda2jdUnpR83YRtZdNc
         5O9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=XH+yhvEv;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f2CVbo4iFRgkm6egBoV0zn8ROn3YXbfZe1nM7EvzU4M=;
        b=jhOfS/Ubc1DHBWd+cNEQtz/UHbS+H9GDpBzDckxcXeY/ZZrD7NXoBBehqDi6ovzRv3
         ZjOa9T55prl77TsQ3A32gaXVU1lUJliMSqw9BcPXCjqgi1/dMN2yMFX0Bw+zhmsgFMow
         2JhJ1VnRZa2hECO4SnitPml8H2BSRMigHIR7HiaXV4cwmitYbF5Xh68z84RsyJ8NgRDZ
         qzznkOYEmqWHB2euiCYiZ/xjPft3PSzZehEbnck9j8hnQVEBgWtlRZy0mzq+phTCk0yL
         e4/kLkMSTV/+zs8tVpF3TvQm4pUJQQlnPmq03uRjMmFHuZb1s6JYs9jpn4xtJCcTJRB6
         01Qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f2CVbo4iFRgkm6egBoV0zn8ROn3YXbfZe1nM7EvzU4M=;
        b=FYTqfaqg0Im7yguIxUSupiAPOVSlyFhGowsCJiZ0oS8BwX/CLpAXYI+fn8NLKNUOIh
         u4e5GFyixMVBr0p4WOG/ObJ0UQXq8wbtvCSwUO//uoQ5Rfok8TixIEGDryOxLqdVezbY
         59/4azTBjvw6hcGAOJP32TKlgcydbMUF5V3GJMRBg/HgDh2AQ7Hgzsz6Ke42OLv9Bx+I
         kBOQcX6c5l2ptqfoLqERN7qAFAb8TcupJ13sh30/h1oQ9NL9naI7j+hrLyOAQEhIn1Dl
         HTvMkoynfz2VYtfitoHCYmWqCN3xTmWpakV+Rqzys1Q7KYtmKqQ9tQNyA1QwXdgWFtMf
         XvsA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUzM4zQi9bQBhBqycr9h6CMt1YK8tz25fWvrBOngakszamlvWXb
	o15dnldcDeVYV9/z8Sj9c78=
X-Google-Smtp-Source: APXvYqz3vmghJx1qwH9HbqMsLKzMzooXWLTYQR/3xEZR/ZyySuBs7XvGpnTSl5zZWlNzqWflSl/bTA==
X-Received: by 2002:a63:c04f:: with SMTP id z15mr6407253pgi.52.1575502448741;
        Wed, 04 Dec 2019 15:34:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b416:: with SMTP id x22ls219618plr.0.gmail; Wed, 04
 Dec 2019 15:34:08 -0800 (PST)
X-Received: by 2002:a17:90a:200d:: with SMTP id n13mr6196625pjc.16.1575502448302;
        Wed, 04 Dec 2019 15:34:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575502448; cv=none;
        d=google.com; s=arc-20160816;
        b=vwIpnOudD9rDzRBjnuoFG+9gqoAnlc2ajrwN6EKbYmZeS8xUc1F+UNcxVVakcca2JT
         B3o/qE0E1UpdNNQbwPvmSAPlYg3zoqyndm8+OeU4EO9Be5ZDVJRpDPFisoA1B7zu2vnM
         4O+gC23A6yTKwtJdJpWE04TFkj+yxfklFjEMEwCOrWgF8WxIemAwDKMzwWPsL0pKb+89
         bn+ZhD8FIE33KSqjUxN2/EszMr0fLV8EikqbrxBZwqEc/gHGxGnJpZpGwl57sZRKyX1s
         eee9jvYYbXp7j4OyPHhdZvYl3GZO757y4rgIkEa6wGMtsKDn4P0ivK1RdFzHuF41mWyz
         LNlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=YKHw99N+Y+VmT/WvGATBE/nA7TXDEC7dotgW1sbKQFA=;
        b=CDKYz7xckOAWQDWWVioHOO4JmSVdYAvdMUpO/GaZk2egiEn+7rN7/KMoFz+0xtRwmb
         g+y9KtgOiGlGm4e+QgL3oKu+Mw48UCEAqxH/ooOMAvmLBx8UTsJLRI8i34xf0b883Raq
         LM09uP3DJswa/NqrIiTGgaJ4sfeICJDc9PSmZ62AqJ34+LYKNaCaCSFnr3X6DqPIVXg9
         uASlGVOE1FW8IVy55qj0pWLS45nXgVcrzbXp/Z3ucC5qzQbZUtkflrvjiAcMXcxWT5bP
         k/dXx9ZO/VYBVqTU+zhQGlQI9JTFLDsP0b6N+hgp5Q9trMwM0y8EaX6il2L1hMMmDwkn
         +Xgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=XH+yhvEv;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id t34si3776pjb.3.2019.12.04.15.34.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Dec 2019 15:34:08 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id k13so638556pgh.3
        for <kasan-dev@googlegroups.com>; Wed, 04 Dec 2019 15:34:08 -0800 (PST)
X-Received: by 2002:aa7:86c5:: with SMTP id h5mr5940606pfo.259.1575502447890;
        Wed, 04 Dec 2019 15:34:07 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-7daa-d2ea-7edb-cfe8.static.ipv6.internode.on.net. [2001:44b8:1113:6700:7daa:d2ea:7edb:cfe8])
        by smtp.gmail.com with ESMTPSA id k18sm9566997pfe.7.2019.12.04.15.34.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 04 Dec 2019 15:34:07 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Casey Schaufler <casey@schaufler-ca.com>, Dmitry Vyukov <dvyukov@google.com>, syzbot <syzbot+de8d933e7d153aa0c1bb@syzkaller.appspotmail.com>, linux-security-module <linux-security-module@vger.kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, kasan-dev <kasan-dev@googlegroups.com>
Cc: Andrea Arcangeli <aarcange@redhat.com>, Andrew Morton <akpm@linux-foundation.org>, Christian Brauner <christian@brauner.io>, christian@kellner.me, cyphar@cyphar.com, "Reshetova\, Elena" <elena.reshetova@intel.com>, Jason Gunthorpe <jgg@ziepe.ca>, Kees Cook <keescook@chromium.org>, ldv@altlinux.org, LKML <linux-kernel@vger.kernel.org>, Andy Lutomirski <luto@amacapital.net>, Ingo Molnar <mingo@kernel.org>, Peter Zijlstra <peterz@infradead.org>, syzkaller-bugs <syzkaller-bugs@googlegroups.com>, Thomas Gleixner <tglx@linutronix.de>, Al Viro <viro@zeniv.linux.org.uk>, Will Drewry <wad@chromium.org>, Casey Schaufler <casey@schaufler-ca.com>
Subject: Re: INFO: rcu detected stall in sys_kill
In-Reply-To: <f7758e0a-a157-56a2-287e-3d4452d72e00@schaufler-ca.com>
References: <00000000000036decf0598c8762e@google.com> <CACT4Y+YVMUxeLcFMray9n0+cXbVibj5X347LZr8YgvjN5nC8pw@mail.gmail.com> <CACT4Y+asdED7tYv462Ui2OhQVKXVUnC+=fumXR3qM1A4d6AvOQ@mail.gmail.com> <f7758e0a-a157-56a2-287e-3d4452d72e00@schaufler-ca.com>
Date: Thu, 05 Dec 2019 10:34:03 +1100
Message-ID: <87a787ekd0.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=XH+yhvEv;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Hi Casey,

> There haven't been Smack changes recently, so this is
> going to have been introduced elsewhere. I'm perfectly
> willing to accept that Smack is doing something horribly
> wrong WRT rcu, and that it needs repair, but its going to
> be tough for me to track down. I hope someone else is looking
> into this, as my chances of finding the problem are pretty
> slim.

Yeah, I'm having a look, it's probably related to my kasan-vmalloc
stuff. It's currently in a bit of flux as syzkaller finds a bunch of
other bugs with it, once that stablises a bit I'll come back to Smack.

Regards,
Daniel

>
>>>
>>> I see 2 common this across all stalls:
>>> 1. They all happen on the instance that uses smack (which is now
>>> effectively dead), see smack instance here:
>>> https://syzkaller.appspot.com/upstream
>>> 2. They all contain this frame in the stack trace:
>>> free_thread_stack+0x168/0x590 kernel/fork.c:280
>>> The last commit that touches this file is "fork: support VMAP_STACK
>>> with KASAN_VMALLOC".
>>> That may be very likely the root cause. +Daniel
>> I've stopped smack syzbot instance b/c it produces infinite stream of
>> assorted crashes due to this.
>> Please ping syzkaller@googlegroups.com when this is fixed, I will
>> re-enable the instance.
>>
>>>> rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
>>>>         (detected by 1, t=10502 jiffies, g=6629, q=331)
>>>> rcu: All QSes seen, last rcu_preempt kthread activity 10503
>>>> (4294953794-4294943291), jiffies_till_next_fqs=1, root ->qsmask 0x0
>>>> syz-executor.0  R  running task    24648  8293   8292 0x0000400a
>>>> Call Trace:
>>>>   <IRQ>
>>>>   sched_show_task+0x40f/0x560 kernel/sched/core.c:5954
>>>>   print_other_cpu_stall kernel/rcu/tree_stall.h:410 [inline]
>>>>   check_cpu_stall kernel/rcu/tree_stall.h:538 [inline]
>>>>   rcu_pending kernel/rcu/tree.c:2827 [inline]
>>>>   rcu_sched_clock_irq+0x1861/0x1ad0 kernel/rcu/tree.c:2271
>>>>   update_process_times+0x12d/0x180 kernel/time/timer.c:1726
>>>>   tick_sched_handle kernel/time/tick-sched.c:167 [inline]
>>>>   tick_sched_timer+0x263/0x420 kernel/time/tick-sched.c:1310
>>>>   __run_hrtimer kernel/time/hrtimer.c:1514 [inline]
>>>>   __hrtimer_run_queues+0x403/0x840 kernel/time/hrtimer.c:1576
>>>>   hrtimer_interrupt+0x38c/0xda0 kernel/time/hrtimer.c:1638
>>>>   local_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1110 [inline]
>>>>   smp_apic_timer_interrupt+0x109/0x280 arch/x86/kernel/apic/apic.c:1135
>>>>   apic_timer_interrupt+0xf/0x20 arch/x86/entry/entry_64.S:829
>>>>   </IRQ>
>>>> RIP: 0010:__read_once_size include/linux/compiler.h:199 [inline]
>>>> RIP: 0010:check_kcov_mode kernel/kcov.c:70 [inline]
>>>> RIP: 0010:__sanitizer_cov_trace_pc+0x1c/0x50 kernel/kcov.c:102
>>>> Code: cc 07 48 89 de e8 64 02 3b 00 5b 5d c3 cc 48 8b 04 24 65 48 8b 0c 25
>>>> c0 1d 02 00 65 8b 15 b8 81 8b 7e f7 c2 00 01 1f 00 75 2c <8b> 91 80 13 00
>>>> 00 83 fa 02 75 21 48 8b 91 88 13 00 00 48 8b 32 48
>>>> RSP: 0018:ffffc900021c7c28 EFLAGS: 00000246 ORIG_RAX: ffffffffffffff13
>>>> RAX: ffffffff81487433 RBX: 0000000000000000 RCX: ffff88809428a100
>>>> RDX: 0000000000000001 RSI: 00000000fffffffc RDI: ffffea0002479240
>>>> RBP: ffffc900021c7c50 R08: dffffc0000000000 R09: fffffbfff1287025
>>>> R10: fffffbfff1287025 R11: 0000000000000000 R12: dffffc0000000000
>>>> R13: dffffc0000000000 R14: 00000000fffffffc R15: ffff888091c57428
>>>>   free_thread_stack+0x168/0x590 kernel/fork.c:280
>>>>   release_task_stack kernel/fork.c:440 [inline]
>>>>   put_task_stack+0xa3/0x130 kernel/fork.c:451
>>>>   finish_task_switch+0x3f1/0x550 kernel/sched/core.c:3256
>>>>   context_switch kernel/sched/core.c:3388 [inline]
>>>>   __schedule+0x9a8/0xcc0 kernel/sched/core.c:4081
>>>>   preempt_schedule_common kernel/sched/core.c:4236 [inline]
>>>>   preempt_schedule+0xdb/0x120 kernel/sched/core.c:4261
>>>>   ___preempt_schedule+0x16/0x18 arch/x86/entry/thunk_64.S:50
>>>>   __raw_read_unlock include/linux/rwlock_api_smp.h:227 [inline]
>>>>   _raw_read_unlock+0x3a/0x40 kernel/locking/spinlock.c:255
>>>>   kill_something_info kernel/signal.c:1586 [inline]
>>>>   __do_sys_kill kernel/signal.c:3640 [inline]
>>>>   __se_sys_kill+0x5e9/0x6c0 kernel/signal.c:3634
>>>>   __x64_sys_kill+0x5b/0x70 kernel/signal.c:3634
>>>>   do_syscall_64+0xf7/0x1c0 arch/x86/entry/common.c:294
>>>>   entry_SYSCALL_64_after_hwframe+0x49/0xbe
>>>> RIP: 0033:0x422a17
>>>> Code: 44 00 00 48 c7 c2 d4 ff ff ff f7 d8 64 89 02 b8 ff ff ff ff c3 66 2e
>>>> 0f 1f 84 00 00 00 00 00 0f 1f 40 00 b8 3e 00 00 00 0f 05 <48> 3d 01 f0 ff
>>>> ff 0f 83 dd 32 ff ff c3 66 2e 0f 1f 84 00 00 00 00
>>>> RSP: 002b:00007fff38dca538 EFLAGS: 00000293 ORIG_RAX: 000000000000003e
>>>> RAX: ffffffffffffffda RBX: 0000000000000064 RCX: 0000000000422a17
>>>> RDX: 0000000000000bb8 RSI: 0000000000000009 RDI: 00000000fffffffe
>>>> RBP: 0000000000000002 R08: 0000000000000001 R09: 0000000001c62940
>>>> R10: 0000000000000000 R11: 0000000000000293 R12: 0000000000000008
>>>> R13: 00007fff38dca570 R14: 000000000000f0b6 R15: 00007fff38dca580
>>>> rcu: rcu_preempt kthread starved for 10533 jiffies! g6629 f0x2
>>>> RCU_GP_WAIT_FQS(5) ->state=0x0 ->cpu=0
>>>> rcu: RCU grace-period kthread stack dump:
>>>> rcu_preempt     R  running task    29032    10      2 0x80004008
>>>> Call Trace:
>>>>   context_switch kernel/sched/core.c:3388 [inline]
>>>>   __schedule+0x9a8/0xcc0 kernel/sched/core.c:4081
>>>>   schedule+0x181/0x210 kernel/sched/core.c:4155
>>>>   schedule_timeout+0x14f/0x240 kernel/time/timer.c:1895
>>>>   rcu_gp_fqs_loop kernel/rcu/tree.c:1661 [inline]
>>>>   rcu_gp_kthread+0xed8/0x1770 kernel/rcu/tree.c:1821
>>>>   kthread+0x332/0x350 kernel/kthread.c:255
>>>>   ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:352
>>>>
>>>>
>>>> ---
>>>> This bug is generated by a bot. It may contain errors.
>>>> See https://goo.gl/tpsmEJ for more information about syzbot.
>>>> syzbot engineers can be reached at syzkaller@googlegroups.com.
>>>>
>>>> syzbot will keep track of this bug report. See:
>>>> https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
>>>>
>>>> --
>>>> You received this message because you are subscribed to the Google Groups "syzkaller-bugs" group.
>>>> To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller-bugs+unsubscribe@googlegroups.com.
>>>> To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller-bugs/00000000000036decf0598c8762e%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87a787ekd0.fsf%40dja-thinkpad.axtens.net.
