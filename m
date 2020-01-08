Return-Path: <kasan-dev+bncBCMIZB7QWENRBPPJ2XYAKGQE7MRQYJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F0BD133BA4
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Jan 2020 07:20:46 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id o18sf1387267qtt.19
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Jan 2020 22:20:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578464445; cv=pass;
        d=google.com; s=arc-20160816;
        b=yFfQ7bVl/B3xgc48TeBQ1hP6xy6c39fJSsJY+1K56XLyXp1rCrfHFD1ZNfXYwMKsC6
         MMnR6g3niMVpGMAKP/DAHJYj4xas8XdH/DwepkenZe7tuG0mQZfHxKQH9lPhOxNx2Iiy
         w+3YOkzO5uxnn81X2Wifr//JrpWGTaYu1FMm3wOjZOaQVEGfXmw06V0sBKJtttk95Ky3
         tplhm5un+6CM9kr0OVW/IyLIR+zzji45sjEAwIK1ibVEcIxtKLRSEbvf2YOmmlYZJYub
         Crm0VP3FSgaSTOLxe4mlAaJkyyiFao8hh+mgMgkpQLEoH+R9bhXZLqBkIBzXLl4e7VyK
         JVew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=02JNkhu7N4EaWbH90QY6srSnyFfiCwA/gHO6hGfweBw=;
        b=ft1tSLs0sV6titVy/TdHPBZygW5juwqRTJ/Tw37TITCv5ZFn+qIV84GVWORF392xtW
         tx5BY2Qfk7WQjoC6JgnFePspWP1UcHgHV2sLA62lUk/eu/YrkTBANm3yMi3ZIabchw/d
         aGajkzBfGeGzQ7M5B9X55P+ZaJVPO2MxiKpRD17lviYrVmtv9cGeGzS+k68cpqxm/hjn
         arUivcItrIrZ4pc8/qZq3q9iYO9U30FcQVmfdzkqxDyeezhat3LBI1hDqnCchGUWoaAF
         U0zq7GsocHVe8s+qOpSpePaxPutej3jrpWdnIXtVjOw+9s7tKShZZxm3KdlHa2O49Hef
         NVhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vpgxkWKp;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=02JNkhu7N4EaWbH90QY6srSnyFfiCwA/gHO6hGfweBw=;
        b=eLvC0KpSa4dn5PbpYwM313yeVJUut7f5NhuKkGkR2RkVXmYz7pTl15bqKgawSeTAm6
         p9GvJxlFkfuRuw2fLo5qXVwXR8IYAppO2HTWPrkcY0s4TgiASGWyr8UBI+AYw7ZW4FHw
         nZAQwsroHh1Bs2rAd90wS2nEm3K4gnlmx/VZjVbeJpAYjE348I00ZtEY3P2gAFrqtKro
         QfZoXzBADSwiHOBQNRv584vuZr7hwT+HxlrsnzborkyMYG7B1VPipSVz14YcXN6Eol0G
         Zl8nJ4uwplcLhCITY2u4orcEOArtmwJH2Y/vlpsrB0h4uW+xzoWWGCzo4p6ZIpNBJfBF
         zfvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=02JNkhu7N4EaWbH90QY6srSnyFfiCwA/gHO6hGfweBw=;
        b=CsIJdBNS5JItbnlK6fyqtcaMEjkYGa3Zbvod1DQ5uoUm/WTpbOEl00/TOR16p5LvIO
         sjYb1H5+WXJnth1BeT3b0ktkG8lagiqxmxVh8DuU3BUV3f6r9/IMqNWSQAZWEH/k626h
         XSQUfbAN15Av0L1nfPsEsbb5y6v4/QOReOD3KN4wlGr0FPSNj1bfUd9OmrwTDaenQkNW
         fBSlgSuUUj1j3u+hQzhslEpR/HGyA0V58JemEx0cW2vuMzKJK5Uj1yLBgihrLrZWZXvu
         M6cOS4ARZD7Z4L2jdxdSTPHEMY193cH/n9ehd2+MI/rMnUO9v8T0aIpceGNSIbDDoa0E
         sBew==
X-Gm-Message-State: APjAAAXi6wGxvgov4O/ztEdfsBCXkzK136RetpcxGJqVRPLSoyQh7YNs
	JC6zJOPlTg+yEdJQwtF0tbs=
X-Google-Smtp-Source: APXvYqx9i7EbQ/9tyqrF2KxJBMueSqLj1yP6O4yMpph20LUSINnQ1VGl43aQZYVAJQ76MmwqQPXuhw==
X-Received: by 2002:a37:8306:: with SMTP id f6mr2898991qkd.372.1578464445137;
        Tue, 07 Jan 2020 22:20:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:4bd5:: with SMTP id y204ls855117qka.4.gmail; Tue, 07 Jan
 2020 22:20:44 -0800 (PST)
X-Received: by 2002:a05:620a:4db:: with SMTP id 27mr2968175qks.146.1578464444754;
        Tue, 07 Jan 2020 22:20:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578464444; cv=none;
        d=google.com; s=arc-20160816;
        b=RzrU0/jBwY20yrlDFJ/qoA7hcQB0pU2NBR5rrY4g6LWDkBAcxmlPhzBY/QKrSZ5cwV
         zEycMXIub4j698QIVDX2UH7spK7InleGS8Rw1DfMz7AdCGmcn/rDeHEgduJwt/jW7CHb
         /j+Y2BXMmBtpGlyHxiG7wWyaNvk86JgkcHmXDH37JYk5zbkdQ5dmI+BDUq1VmdFGpAaa
         +CjzcTfYspMaF7N5H+faCpR3fm1n1cBHWy17dtvsN79VxoJaDXo4R8L5UgK/4HiRBJWt
         EQtOSRU6dExAhk+18b9Zl4R9zyY8bK8jKSTVECRQTF7rjLCuF51plR/3Jz7wUe4Mq4mk
         NqdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AK1iJurazYPeDznylfVGz03NF8tJ90Gw1QHQnKAzHGU=;
        b=TeG8TN8UmYAnPSiMVMflCv4MumoB8Xf1nMdOA+5gYiYnUy9yYrjQnp/sJ5G+GLNEAc
         pKDHVBLxUBo3eE1mI7XbXQ7Ri3BCM/bOXfx8fzraKEMUlU8TbFCT4o9hOB5t8nu1JNl+
         HPEAh0nyAr/7YbcPDlAHD3HHj9VS+NsNSL28zdMxn+hPEr0MZJfizKuzHotoePth1dRq
         yD9TH0DXsVZNRWqGKelTOgO6Ci+x6OwmcF2CKR9LAhPbcqk+lIdnjadIThtddLDSNKnu
         MNhtCAhmQqkHvFlwAIRtTyVLGQxZlJUZ8AXwKzIlQyG03FH6R6ojVEKsV6ZYXWSl7rH4
         4i/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vpgxkWKp;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id r62si72145qkc.6.2020.01.07.22.20.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Jan 2020 22:20:44 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id x129so1683338qke.8
        for <kasan-dev@googlegroups.com>; Tue, 07 Jan 2020 22:20:44 -0800 (PST)
X-Received: by 2002:a37:5841:: with SMTP id m62mr2846731qkb.256.1578464444103;
 Tue, 07 Jan 2020 22:20:44 -0800 (PST)
MIME-Version: 1.0
References: <00000000000036decf0598c8762e@google.com> <CACT4Y+YVMUxeLcFMray9n0+cXbVibj5X347LZr8YgvjN5nC8pw@mail.gmail.com>
 <CACT4Y+asdED7tYv462Ui2OhQVKXVUnC+=fumXR3qM1A4d6AvOQ@mail.gmail.com>
 <f7758e0a-a157-56a2-287e-3d4452d72e00@schaufler-ca.com> <87a787ekd0.fsf@dja-thinkpad.axtens.net>
 <87h81zax74.fsf@dja-thinkpad.axtens.net>
In-Reply-To: <87h81zax74.fsf@dja-thinkpad.axtens.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 8 Jan 2020 07:20:32 +0100
Message-ID: <CACT4Y+b+Vx1FeCmhMAYq-g3ObHdMPOsWxouyXXUr7S5OjNiVGQ@mail.gmail.com>
Subject: Re: INFO: rcu detected stall in sys_kill
To: Daniel Axtens <dja@axtens.net>
Cc: Casey Schaufler <casey@schaufler-ca.com>, 
	syzbot <syzbot+de8d933e7d153aa0c1bb@syzkaller.appspotmail.com>, 
	linux-security-module <linux-security-module@vger.kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrea Arcangeli <aarcange@redhat.com>, Andrew Morton <akpm@linux-foundation.org>, 
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
 header.i=@google.com header.s=20161025 header.b=vpgxkWKp;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
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

On Tue, Dec 17, 2019 at 2:39 PM Daniel Axtens <dja@axtens.net> wrote:
>
> Daniel Axtens <dja@axtens.net> writes:
>
> > Hi Casey,
> >
> >> There haven't been Smack changes recently, so this is
> >> going to have been introduced elsewhere. I'm perfectly
> >> willing to accept that Smack is doing something horribly
> >> wrong WRT rcu, and that it needs repair, but its going to
> >> be tough for me to track down. I hope someone else is looking
> >> into this, as my chances of finding the problem are pretty
> >> slim.
> >
> > Yeah, I'm having a look, it's probably related to my kasan-vmalloc
> > stuff. It's currently in a bit of flux as syzkaller finds a bunch of
> > other bugs with it, once that stablises a bit I'll come back to Smack.
>
> I have had a brief and wildly unsuccessful look at this. I'm happy to
> come back to it and go over it with a finer toothed comb, but it will
> almost certainly have to wait until next year.
>
> I don't think it's related to RCU, we also have a plain lockup:
> https://syzkaller.appspot.com/bug?id=be03729d17bb3b2df1754a7486a8f8628f6ff1ec
>
> Dmitry, I've been really struggling to repro this locally, even with
> your config. Is there an easy way to see the kernel command line you
> booted with and anything else that makes this image special? I have zero
> experience with smack so this is a steep learning curve.

I temporarily re-enabled smack instance and it produced another 50
stalls all over the kernel, and now keeps spewing a dozen every hour.

I've mailed 3 new samples, you can see them here:
https://syzkaller.appspot.com/bug?extid=de8d933e7d153aa0c1bb

The config is provided, command line args are here:
https://github.com/google/syzkaller/blob/master/dashboard/config/upstream-smack.cmdline
Some non-default sysctls that syzbot sets are here:
https://github.com/google/syzkaller/blob/master/dashboard/config/upstream.sysctl
Image can be downloaded from here:
https://github.com/google/syzkaller/blob/master/docs/syzbot.md#crash-does-not-reproduce
syzbot uses GCE VMs with 2 CPUs and 7.5GB memory, but this does not
look to be virtualization-related (?) so probably should reproduce in
qemu too.



> Regards,
> Daniel
>
> >
> > Regards,
> > Daniel
> >
> >>
> >>>>
> >>>> I see 2 common this across all stalls:
> >>>> 1. They all happen on the instance that uses smack (which is now
> >>>> effectively dead), see smack instance here:
> >>>> https://syzkaller.appspot.com/upstream
> >>>> 2. They all contain this frame in the stack trace:
> >>>> free_thread_stack+0x168/0x590 kernel/fork.c:280
> >>>> The last commit that touches this file is "fork: support VMAP_STACK
> >>>> with KASAN_VMALLOC".
> >>>> That may be very likely the root cause. +Daniel
> >>> I've stopped smack syzbot instance b/c it produces infinite stream of
> >>> assorted crashes due to this.
> >>> Please ping syzkaller@googlegroups.com when this is fixed, I will
> >>> re-enable the instance.
> >>>
> >>>>> rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
> >>>>>         (detected by 1, t=10502 jiffies, g=6629, q=331)
> >>>>> rcu: All QSes seen, last rcu_preempt kthread activity 10503
> >>>>> (4294953794-4294943291), jiffies_till_next_fqs=1, root ->qsmask 0x0
> >>>>> syz-executor.0  R  running task    24648  8293   8292 0x0000400a
> >>>>> Call Trace:
> >>>>>   <IRQ>
> >>>>>   sched_show_task+0x40f/0x560 kernel/sched/core.c:5954
> >>>>>   print_other_cpu_stall kernel/rcu/tree_stall.h:410 [inline]
> >>>>>   check_cpu_stall kernel/rcu/tree_stall.h:538 [inline]
> >>>>>   rcu_pending kernel/rcu/tree.c:2827 [inline]
> >>>>>   rcu_sched_clock_irq+0x1861/0x1ad0 kernel/rcu/tree.c:2271
> >>>>>   update_process_times+0x12d/0x180 kernel/time/timer.c:1726
> >>>>>   tick_sched_handle kernel/time/tick-sched.c:167 [inline]
> >>>>>   tick_sched_timer+0x263/0x420 kernel/time/tick-sched.c:1310
> >>>>>   __run_hrtimer kernel/time/hrtimer.c:1514 [inline]
> >>>>>   __hrtimer_run_queues+0x403/0x840 kernel/time/hrtimer.c:1576
> >>>>>   hrtimer_interrupt+0x38c/0xda0 kernel/time/hrtimer.c:1638
> >>>>>   local_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1110 [inline]
> >>>>>   smp_apic_timer_interrupt+0x109/0x280 arch/x86/kernel/apic/apic.c:1135
> >>>>>   apic_timer_interrupt+0xf/0x20 arch/x86/entry/entry_64.S:829
> >>>>>   </IRQ>
> >>>>> RIP: 0010:__read_once_size include/linux/compiler.h:199 [inline]
> >>>>> RIP: 0010:check_kcov_mode kernel/kcov.c:70 [inline]
> >>>>> RIP: 0010:__sanitizer_cov_trace_pc+0x1c/0x50 kernel/kcov.c:102
> >>>>> Code: cc 07 48 89 de e8 64 02 3b 00 5b 5d c3 cc 48 8b 04 24 65 48 8b 0c 25
> >>>>> c0 1d 02 00 65 8b 15 b8 81 8b 7e f7 c2 00 01 1f 00 75 2c <8b> 91 80 13 00
> >>>>> 00 83 fa 02 75 21 48 8b 91 88 13 00 00 48 8b 32 48
> >>>>> RSP: 0018:ffffc900021c7c28 EFLAGS: 00000246 ORIG_RAX: ffffffffffffff13
> >>>>> RAX: ffffffff81487433 RBX: 0000000000000000 RCX: ffff88809428a100
> >>>>> RDX: 0000000000000001 RSI: 00000000fffffffc RDI: ffffea0002479240
> >>>>> RBP: ffffc900021c7c50 R08: dffffc0000000000 R09: fffffbfff1287025
> >>>>> R10: fffffbfff1287025 R11: 0000000000000000 R12: dffffc0000000000
> >>>>> R13: dffffc0000000000 R14: 00000000fffffffc R15: ffff888091c57428
> >>>>>   free_thread_stack+0x168/0x590 kernel/fork.c:280
> >>>>>   release_task_stack kernel/fork.c:440 [inline]
> >>>>>   put_task_stack+0xa3/0x130 kernel/fork.c:451
> >>>>>   finish_task_switch+0x3f1/0x550 kernel/sched/core.c:3256
> >>>>>   context_switch kernel/sched/core.c:3388 [inline]
> >>>>>   __schedule+0x9a8/0xcc0 kernel/sched/core.c:4081
> >>>>>   preempt_schedule_common kernel/sched/core.c:4236 [inline]
> >>>>>   preempt_schedule+0xdb/0x120 kernel/sched/core.c:4261
> >>>>>   ___preempt_schedule+0x16/0x18 arch/x86/entry/thunk_64.S:50
> >>>>>   __raw_read_unlock include/linux/rwlock_api_smp.h:227 [inline]
> >>>>>   _raw_read_unlock+0x3a/0x40 kernel/locking/spinlock.c:255
> >>>>>   kill_something_info kernel/signal.c:1586 [inline]
> >>>>>   __do_sys_kill kernel/signal.c:3640 [inline]
> >>>>>   __se_sys_kill+0x5e9/0x6c0 kernel/signal.c:3634
> >>>>>   __x64_sys_kill+0x5b/0x70 kernel/signal.c:3634
> >>>>>   do_syscall_64+0xf7/0x1c0 arch/x86/entry/common.c:294
> >>>>>   entry_SYSCALL_64_after_hwframe+0x49/0xbe
> >>>>> RIP: 0033:0x422a17
> >>>>> Code: 44 00 00 48 c7 c2 d4 ff ff ff f7 d8 64 89 02 b8 ff ff ff ff c3 66 2e
> >>>>> 0f 1f 84 00 00 00 00 00 0f 1f 40 00 b8 3e 00 00 00 0f 05 <48> 3d 01 f0 ff
> >>>>> ff 0f 83 dd 32 ff ff c3 66 2e 0f 1f 84 00 00 00 00
> >>>>> RSP: 002b:00007fff38dca538 EFLAGS: 00000293 ORIG_RAX: 000000000000003e
> >>>>> RAX: ffffffffffffffda RBX: 0000000000000064 RCX: 0000000000422a17
> >>>>> RDX: 0000000000000bb8 RSI: 0000000000000009 RDI: 00000000fffffffe
> >>>>> RBP: 0000000000000002 R08: 0000000000000001 R09: 0000000001c62940
> >>>>> R10: 0000000000000000 R11: 0000000000000293 R12: 0000000000000008
> >>>>> R13: 00007fff38dca570 R14: 000000000000f0b6 R15: 00007fff38dca580
> >>>>> rcu: rcu_preempt kthread starved for 10533 jiffies! g6629 f0x2
> >>>>> RCU_GP_WAIT_FQS(5) ->state=0x0 ->cpu=0
> >>>>> rcu: RCU grace-period kthread stack dump:
> >>>>> rcu_preempt     R  running task    29032    10      2 0x80004008
> >>>>> Call Trace:
> >>>>>   context_switch kernel/sched/core.c:3388 [inline]
> >>>>>   __schedule+0x9a8/0xcc0 kernel/sched/core.c:4081
> >>>>>   schedule+0x181/0x210 kernel/sched/core.c:4155
> >>>>>   schedule_timeout+0x14f/0x240 kernel/time/timer.c:1895
> >>>>>   rcu_gp_fqs_loop kernel/rcu/tree.c:1661 [inline]
> >>>>>   rcu_gp_kthread+0xed8/0x1770 kernel/rcu/tree.c:1821
> >>>>>   kthread+0x332/0x350 kernel/kthread.c:255
> >>>>>   ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:352
> >>>>>
> >>>>>
> >>>>> ---
> >>>>> This bug is generated by a bot. It may contain errors.
> >>>>> See https://goo.gl/tpsmEJ for more information about syzbot.
> >>>>> syzbot engineers can be reached at syzkaller@googlegroups.com.
> >>>>>
> >>>>> syzbot will keep track of this bug report. See:
> >>>>> https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
> >>>>>
> >>>>> --
> >>>>> You received this message because you are subscribed to the Google Groups "syzkaller-bugs" group.
> >>>>> To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller-bugs+unsubscribe@googlegroups.com.
> >>>>> To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller-bugs/00000000000036decf0598c8762e%40google.com.
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87h81zax74.fsf%40dja-thinkpad.axtens.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb%2BVx1FeCmhMAYq-g3ObHdMPOsWxouyXXUr7S5OjNiVGQ%40mail.gmail.com.
