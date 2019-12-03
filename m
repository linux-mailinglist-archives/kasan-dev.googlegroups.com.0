Return-Path: <kasan-dev+bncBCMIZB7QWENRBCF4TDXQKGQEZFKZQQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 3564A10F9E7
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Dec 2019 09:34:17 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id l1sf1681161qvu.13
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Dec 2019 00:34:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575362056; cv=pass;
        d=google.com; s=arc-20160816;
        b=G7N5oY2p242kaF/kW8zQF+zyzvwf/I7XWe1tgGzVAa8XVdLdnZPdiY9UOQHWT5CbJB
         NuU95/DBlgDHCugS6B36wN7+PuZjQoRPwekKk6mVQud74RhmdTsB/vwfIRQSHZ8L0xEh
         FrWERvDFnskB8P7puq2pE2R4GCiU0/EVOGFLKVau+qkp4Og2mIS/92+eyV0uuf0cNzaH
         AWGzaW/rKTmHIsXiZtqyJUxibqK06pWVszFnYSUzWP5JtVf4jT7dSDsbXlvDoBmpZMzm
         NrIGYgGIVEF7digDJaW/FnzAtSowngO5q2BiqKuZQrOsGvYC4O0d5RY4AgxEKImCGh+7
         aoBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LjWRySVeBSF5tdmIFDS3qb5TAYQYoFXj6i9aGK6MRok=;
        b=xfM0o2DIZFcUcT6Jtg/ciK5OOzVy2XcRoujTBHpU0MrKo6OLSxVtijE4WO2VRSRKDr
         yAm9Gj1wq7YKRgCsetnFUDUaBmzwxb4bXyb7UwZHdGxLmiO4/fOLLk6L2Q3uAVjb8otd
         hwrTuNBrAQTDV1pFHyFQ0MOHqqNh5ciaXFAwpM9TCA+BBKeMNdx9qUqtgZVC6Hu3DmEi
         iyaku4rfaITfN17MnPIsUFjgzstT3BCwhlJ1n/YskXPbgYvq77ppVfSdu1kIXXILZmz+
         W4VXmy2WZrFaBWnxW223EpkyzcFW/Pe1ZZ5gYNf6sU26fBn3WDeMSTA8uOsc7d2P7JTu
         dBew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=keCkCayQ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LjWRySVeBSF5tdmIFDS3qb5TAYQYoFXj6i9aGK6MRok=;
        b=jFvv6QqElfqLl68atBntFauy/XX/YzMUmHKbR/0DB0aaHQlR5pxUjTIOADGIrY0XoK
         vYjgkw58snjL5NP1PD1DXTzx/1lylRWcfdiwQOA9MzHndrqmDJhksDTwcN89v+QiBLsx
         RrHhSZTVe5wQTnyfeInyYBt9F/aMlAAgTqWX9dVaW2qrIFOE5drgbuGRAckWC2uR+HxW
         ld+74O2ZzN8aZ8C94jy50PST9g2MbbRdkpRMdz6T2y0+LUNnhY3ep/OEjYqt7/TTODUa
         W5Gl0ml6JZ7RNTzRjmqElXB2ywZmIKYvllWkPe2EdeLZySRUboBubsduNVz1mSygnseI
         rBPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LjWRySVeBSF5tdmIFDS3qb5TAYQYoFXj6i9aGK6MRok=;
        b=jvq/9p+yjtHT5U+hPP4f8m9VcnU501VSi9UySSLLL6N4MvEfVph9y8UOYJWZqlzUYb
         Ilj+C75PEJcpudthmPw5amfOIfeAowR+VsahBcYJVB5huM0/K9/YU2Aw9Vtn/emI2org
         yDAIM+vI9tQoRlc1dIA82/MuBgIDCG5hwAfnZk9uD3H2MQMWxpuDHiM3Dn7eq0UKgxsg
         KM+4rICIlws4B2OfD1h23fiAANHk9j8N/5cbxMvfo9XLrbGjoEJ6QMV/H/VilFFz2qvd
         210bA5O6O5CSDIOWX1s53eJ6ctGOv7nYpIlMPNCA7lVGl31vucLvuYhXF1VwIxCi8mel
         aXhQ==
X-Gm-Message-State: APjAAAX3PR+PzKMLYbe6Jf0/Jbwb3crRyh3JeCpv52EvWzzbC0sDXBN9
	jTwIyxoGszcrgLh5Kg8Ygu0=
X-Google-Smtp-Source: APXvYqwJdiu1APiXihD/UB+fG/xyGEt7FCCcEsfTOfmk5iL1usbUFPHlSfJ4xP4pPD0UsV/AhFFdxw==
X-Received: by 2002:a05:620a:711:: with SMTP id 17mr353890qkc.348.1575362056111;
        Tue, 03 Dec 2019 00:34:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e288:: with SMTP id r8ls505553qvl.2.gmail; Tue, 03 Dec
 2019 00:34:15 -0800 (PST)
X-Received: by 2002:a0c:e503:: with SMTP id l3mr3924609qvm.92.1575362055782;
        Tue, 03 Dec 2019 00:34:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575362055; cv=none;
        d=google.com; s=arc-20160816;
        b=ucH/MN0sI5JGq/n19VAQVval/JXVRBn4j2Iae/vt7NNx1l1goAC8+vvsYU+Nz6aBNU
         4zWEkmcM1P2rUTbc3DqxWH3eBkA7bsq1jTvKU0Bt9Egzpkh22QHzz4wVg2w9tZkTETxl
         uZyje5zYHtLr4FlvetXiwpTWfGj6QaRqq6sgkzAzEACNboidmLqOrd8c9Q3Vj0y1201e
         i90V6p44RfllKvbMY4OjB/85SvL5++0ETyJk4Mt05cxJILKZmcy+yS79MgOOxlNIIdGU
         cl7k2CXhqTZyxdcqJkHGjnAkTTVsrMaUnZRT/kAJbCGlzqpGJz1G5ADDRGcDoSJr5wKK
         t1Jw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nJg2KP6JhpBwQA6aoEbxzCR7hQQISOOcMw3t/Of3n3s=;
        b=iCDcMoj2qUv/shk031S0o1ATkE4wlOOfwqunSPcaxxrwOsrr+RfOvD2txfb6kn7qRd
         BOqeivtWENWNSTykYPqykJdpaB2A1eGNrdKKCNTl4A581PVLUO4S2N5hydG7dcWqcTnP
         Rm2OBInz6b8BBbV1rs1UuD7/dMY+HOLInctahcqOCuFiemFhA+QoyJd6e5UKiVZoMiH1
         svv8/ZcWtDRhhPvCXJ1uYwoEEWKT8jKtlmD6l3R1jCHAsqUhkak5E3FDYlSghf/TGOYk
         QZMU1x5K1hHnBFHjbC5pFQZO+SnN5JXg97/sI+7Ht8TmqjEmprPPWZvJNgGcI4bAMjC2
         q+nQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=keCkCayQ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id n22si103450qkg.2.2019.12.03.00.34.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Dec 2019 00:34:15 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id c124so2677381qkg.0
        for <kasan-dev@googlegroups.com>; Tue, 03 Dec 2019 00:34:15 -0800 (PST)
X-Received: by 2002:a37:9d12:: with SMTP id g18mr873425qke.43.1575362052736;
 Tue, 03 Dec 2019 00:34:12 -0800 (PST)
MIME-Version: 1.0
References: <000000000000d5b2330598c87921@google.com>
In-Reply-To: <000000000000d5b2330598c87921@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 3 Dec 2019 09:34:01 +0100
Message-ID: <CACT4Y+a-YX9_q+pPnZ16CTn=1hvyduGDRt20YUgn8B40nkRwWw@mail.gmail.com>
Subject: Re: INFO: rcu detected stall in security_file_free
To: syzbot <syzbot+6176df02eb1a01d00646@syzkaller.appspotmail.com>, 
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
 header.i=@google.com header.s=20161025 header.b=keCkCayQ;       spf=pass
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
<syzbot+6176df02eb1a01d00646@syzkaller.appspotmail.com> wrote:
>
> Hello,
>
> syzbot found the following crash on:
>
> HEAD commit:    596cf45c Merge branch 'akpm' (patches from Andrew)
> git tree:       upstream
> console output: https://syzkaller.appspot.com/x/log.txt?x=1327942ae00000
> kernel config:  https://syzkaller.appspot.com/x/.config?x=9bbcda576154a4b4
> dashboard link: https://syzkaller.appspot.com/bug?extid=6176df02eb1a01d00646
> compiler:       clang version 9.0.0 (/home/glider/llvm/clang
> 80fee25776c2fb61e74c1ecb1a523375c2500b69)
>
> Unfortunately, I don't have any reproducer for this crash yet.
>
> IMPORTANT: if you fix the bug, please add the following tag to the commit:
> Reported-by: syzbot+6176df02eb1a01d00646@syzkaller.appspotmail.com

Something seriously broke in smack+kasan+vmap stacks, we now have 60
rcu stalls all over the place and counting. This is one of the
samples. Let's dup all of them to a single one and continue the
discussion there:

#syz dup: INFO: rcu detected stall in sys_kill

> rcu: INFO: rcu_preempt self-detected stall on CPU
> rcu:    0-...!: (10499 ticks this GP) idle=f6a/1/0x4000000000000002
> softirq=9928/9928 fqs=38
>         (t=10501 jiffies g=6205 q=398)
> rcu: rcu_preempt kthread starved for 10424 jiffies! g6205 f0x0
> RCU_GP_WAIT_FQS(5) ->state=0x0 ->cpu=1
> rcu: RCU grace-period kthread stack dump:
> rcu_preempt     R  running task    29032    10      2 0x80004000
> Call Trace:
>   context_switch kernel/sched/core.c:3385 [inline]
>   __schedule+0x9a0/0xcc0 kernel/sched/core.c:4081
>   schedule+0x181/0x210 kernel/sched/core.c:4155
>   schedule_timeout+0x14f/0x240 kernel/time/timer.c:1895
>   rcu_gp_fqs_loop kernel/rcu/tree.c:1661 [inline]
>   rcu_gp_kthread+0xed8/0x1770 kernel/rcu/tree.c:1821
>   kthread+0x332/0x350 kernel/kthread.c:255
>   ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:352
> NMI backtrace for cpu 0
> CPU: 0 PID: 8045 Comm: syz-executor.5 Not tainted 5.4.0-syzkaller #0
> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS
> Google 01/01/2011
> Call Trace:
>   <IRQ>
>   __dump_stack lib/dump_stack.c:77 [inline]
>   dump_stack+0x1fb/0x318 lib/dump_stack.c:118
>   nmi_cpu_backtrace+0xaf/0x1a0 lib/nmi_backtrace.c:101
>   nmi_trigger_cpumask_backtrace+0x174/0x290 lib/nmi_backtrace.c:62
>   arch_trigger_cpumask_backtrace+0x10/0x20 arch/x86/kernel/apic/hw_nmi.c:38
>   trigger_single_cpu_backtrace include/linux/nmi.h:164 [inline]
>   rcu_dump_cpu_stacks+0x15a/0x220 kernel/rcu/tree_stall.h:254
>   print_cpu_stall kernel/rcu/tree_stall.h:455 [inline]
>   check_cpu_stall kernel/rcu/tree_stall.h:529 [inline]
>   rcu_pending kernel/rcu/tree.c:2827 [inline]
>   rcu_sched_clock_irq+0xe25/0x1ad0 kernel/rcu/tree.c:2271
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
> RIP: 0010:__sanitizer_cov_trace_pc+0x0/0x50 kernel/kcov.c:98
> Code: 66 2e 0f 1f 84 00 00 00 00 00 55 48 89 e5 53 48 89 fb e8 13 00 00 00
> 48 8b 3d 34 e7 cc 07 48 89 de e8 64 02 3b 00 5b 5d c3 cc <48> 8b 04 24 65
> 48 8b 0c 25 c0 1d 02 00 65 8b 15 b8 81 8b 7e f7 c2
> RSP: 0018:ffffc90001f87a90 EFLAGS: 00000246 ORIG_RAX: ffffffffffffff13
> RAX: 1ffff11013f36931 RBX: ffffea00029e3f40 RCX: 0000000000000000
> RDX: 0000000000000000 RSI: 00000000fffffffc RDI: ffffea00029e3f40
> RBP: ffffc90001f87ab8 R08: dffffc0000000000 R09: fffffbfff120248a
> R10: fffffbfff120248a R11: 0000000000000000 R12: ffff88809f9b4a20
> R13: dffffc0000000000 R14: 00000000fffffffc R15: ffff8880a8747628
>   free_thread_stack+0x168/0x590 kernel/fork.c:280
>   release_task_stack kernel/fork.c:440 [inline]
>   put_task_stack+0xa3/0x130 kernel/fork.c:451
>   finish_task_switch+0x3f1/0x550 kernel/sched/core.c:3256
>   context_switch kernel/sched/core.c:3388 [inline]
>   __schedule+0x9a8/0xcc0 kernel/sched/core.c:4081
>   preempt_schedule_irq+0xc1/0x140 kernel/sched/core.c:4338
>   retint_kernel+0x1b/0x2b
> RIP: 0010:arch_local_irq_restore arch/x86/include/asm/paravirt.h:752
> [inline]
> RIP: 0010:kmem_cache_free+0xc8/0xf0 mm/slab.c:3695
> Code: 58 07 00 74 42 4c 89 f7 57 9d 0f 1f 44 00 00 e8 0e 98 ca ff eb 19 e8
> a7 95 ca ff 48 83 3d 07 f7 58 07 00 74 24 4c 89 f7 57 9d <0f> 1f 44 00 00
> 4c 89 e7 4c 89 fe e8 58 01 00 00 5b 41 5c 41 5e 41
> RSP: 0018:ffffc90001f87d10 EFLAGS: 00000286 ORIG_RAX: ffffffffffffff13
> RAX: ffff88809753ced4 RBX: ffff8880aa9eb000 RCX: ffff88809753c640
> RDX: 0000000000000000 RSI: ffffffff83474bc4 RDI: 0000000000000286
> RBP: ffffc90001f87d30 R08: ffff88809753ce98 R09: ffffc90001f87b14
> R10: 000000000000000b R11: 0000000000000000 R12: ffffffff83474bc4
> R13: ffff888095bf2cc0 R14: 0000000000000286 R15: ffff8880a304d1f8
>   security_file_free+0xc4/0xe0 security/security.c:1403
>   file_free fs/file_table.c:55 [inline]
>   __fput+0x506/0x740 fs/file_table.c:298
>   ____fput+0x15/0x20 fs/file_table.c:313
>   task_work_run+0x17e/0x1b0 kernel/task_work.c:113
>   tracehook_notify_resume include/linux/tracehook.h:188 [inline]
>   exit_to_usermode_loop arch/x86/entry/common.c:164 [inline]
>   prepare_exit_to_usermode+0x483/0x5b0 arch/x86/entry/common.c:195
>   syscall_return_slowpath+0x113/0x4a0 arch/x86/entry/common.c:278
>   do_syscall_64+0x11f/0x1c0 arch/x86/entry/common.c:304
>   entry_SYSCALL_64_after_hwframe+0x49/0xbe
> RIP: 0033:0x45e433
> Code: 48 89 ee 48 89 e7 e8 2c 1f fa ff 31 c0 48 89 e2 be 33 89 00 00 89 df
> e8 bb c0 ff ff 85 c0 78 17 48 63 fb b8 03 00 00 00 0f 05 <8b> 44 24 10 48
> 83 c4 38 5b 5d c3 66 90 48 c7 c2 d4 ff ff ff 48 63
> RSP: 002b:00007ffe95171aa0 EFLAGS: 00000246 ORIG_RAX: 0000000000000003
> RAX: 0000000000000000 RBX: 0000000000000004 RCX: 000000000045e433
> RDX: 00007ffe95171aa0 RSI: 0000000000008933 RDI: 0000000000000004
> RBP: 00000000004bfb19 R08: 000000000000000a R09: 000000000000000a
> R10: 0000000000000004 R11: 0000000000000246 R12: 0000000000000003
> R13: 0000000000000006 R14: 0000000000000000 R15: 00007ffe95171d30
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
> To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller-bugs/000000000000d5b2330598c87921%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba-YX9_q%2BpPnZ16CTn%3D1hvyduGDRt20YUgn8B40nkRwWw%40mail.gmail.com.
