Return-Path: <kasan-dev+bncBCMIZB7QWENRBPWGRTUQKGQEO3KEDEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 58D4A61D7E
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Jul 2019 13:04:32 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d6sf5278922pls.17
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Jul 2019 04:04:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562583870; cv=pass;
        d=google.com; s=arc-20160816;
        b=AaRk4NFk2I225dTBFMAmJQxjyqQ+0t700H2FRG2Ne8/N5dSnqdrtXaQabkorOklr23
         7jvCY+zDelU2N374CDu5ky3IeSsKNFlK8vfztyPo7MoMs9QaH2gG1MJUEzxYTtyYuFU7
         C8C9shqiZ86gF89cUdp6x5hIoZFMYsmaepoPl66J+lkY1vQJC3MnruPrCwNizIdxp0bK
         kcndOBbUCC6esEiTV5n08XXzXI7atxpG/34Kt0B8Z54dL6a5LUBJToYpZuPXG5bT/3q8
         s7WRXrVGfZeYBhZiWTzSTkBE+4CbGWMXrheUlnPjG9mrUkitYowqXAI+4xIWYeM2HHXW
         3WkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IZC4P6g/t8aKl1jPPQST4FfFVZ0Pv5lHRkCJNJK44Kc=;
        b=YoPO63Ly37bZReyQzn7YhFzuOhAStShDicvjyGhtM1lokgli/ez0GYlmZGMovmDMz5
         J5guTj/Nj/rd9YaLKmwzx4cLo6EyPcMHQn/18ZjNCz9h3C6MF5w4+PBjcHz95A8/EE0b
         jCnivZ1Nb6DrAuCJLqGB5b5I4+T7OfuWb8ybKoAbzdcqE6DqHfiphTnuRPt3iUZH1Qqz
         M5PrHZK12bu81uaBSJPZ/g31SXVOg9ljYgTXjiBL08jbsOtApBs0pb2u1T2EkCZQ8EJb
         0IFmFzkE+VxHOgXaoGGoMy4RA3d3OrYhs36yuK4bhVnEzPz9uT6AI3Qgi7xoceaYF5Rr
         fFbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dpins7gF;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IZC4P6g/t8aKl1jPPQST4FfFVZ0Pv5lHRkCJNJK44Kc=;
        b=FZPbE/h5wmf9JNpn/gplzjA3ejek/84JBAJlje8+Bqc0AwN/wazq0z3H8MgrZNYog7
         KkcngNlIPuQcC11s4lQSJJCAIjmxxzK3MNgXa3RY0+PUoBL/MVLdCVFsJjgrrQHp0DNw
         PKEde/EPYCiCw//YAZoXctp6E/byE2dlRKX/WK2VpsJ1no/c7s6VwyzZutBNGK6DS7Bc
         Ukjf6P+Y5FECsl7Wv6hLahlMrPh2NncceYLJ1M3eFq18zWlPiDDea0ACRnq8bcQxtq4D
         ONElCC5W+MXALmZeJ5fePGPjdL3T8aXpngtZGosCn8/ojmKDdM7JtjgHKlVlKpwd+Bq3
         cFaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IZC4P6g/t8aKl1jPPQST4FfFVZ0Pv5lHRkCJNJK44Kc=;
        b=LoCyHA3fS0lBjDWqb/uYfcAHPYRs6S2HcHflbzSHYOaeydLjd7YhEooTBvN0mhkrVr
         HPWo8jG2yWg4o5Jbjqes5CqnxNbO+jbn7fYNTe7pnqRX6wxwoJFEnGrYBc5y3XCFVYFp
         WC11ReUZ+vnX6l1iOhU31PfZIDTdTntn1hdrvHSAdQbOk1uf3ET8fiIJY/pJ2LumqtBc
         m3C2Lrbbv8nD6xhwHEBB7trom3tZz3UUue8Ib9lqT6HwfDGJ10W/d71Q3xdFBP4tRxO7
         WrIljp5TMAor1sodH906XzBsL9mMvlZEe45a+XXhFUlh/b0hHJMwi8UR1n6LamLn8EhH
         vElg==
X-Gm-Message-State: APjAAAUSBMZIb8hLVJBs2EbF2/T2oBgtTh76uadg++6myi/moiknwNTy
	xtjRJ57ZG8BTK8V7qweZtoE=
X-Google-Smtp-Source: APXvYqzX1XPFYDJmTTy7JXo0DEHD2zyKNK1AiOvI8fojSoLywJ+5GFlilCzZeY2gyasrZ5IF2sJ+uQ==
X-Received: by 2002:a17:90a:b00b:: with SMTP id x11mr24782129pjq.120.1562583870679;
        Mon, 08 Jul 2019 04:04:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:db53:: with SMTP id u19ls2226122pjx.3.gmail; Mon, 08
 Jul 2019 04:04:30 -0700 (PDT)
X-Received: by 2002:a17:90a:cb8e:: with SMTP id a14mr24195978pju.124.1562583870354;
        Mon, 08 Jul 2019 04:04:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562583870; cv=none;
        d=google.com; s=arc-20160816;
        b=BV03/PL4LGQZ6fcB6we5J//70Ad7tw7gv+kKPCBHcJEoCybEyyBrMq9KD3W6E13Xns
         PEnZwQe2uzwau9qVVojAv4Y7BStwZZE5Ho2mI9HJQd19KrBrMFhB21OiSi2O1EPO9DAc
         oSHuLPnBooMLAoj0d78PyH8ptVT+YdvmjDS0/y7ydg+iNULpcMFzMje3VCPRjzXYRFx9
         T3a8ayzs8MtdRhDMOBfF5aP2MIsITKN5ozTlNq1VDIXrQrttpMq+a8Dvqki+GgTj8mp7
         N5vaCEw+noAikWEML6GZyoTYDvTmLcVP4MpAetHSs+x5TWmijlZEBHGcpXItAAT3YtqC
         YL/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/2IlxMV/t0jFtVN83AfBtLyDts03NQaXCeGrr0PWXu8=;
        b=FX62DUy/z87WalV4t8CwYrfRBJ3lfU3GgtfeGpAU3CLuakNSQxN3+j8hIJaoT4ACM/
         +vqXZM/bDYKE2YR7+J44dmawkAV1Px8BfucTtOErauKObPanVyI1Lcaqf62M4DwbutiY
         joKTh5WP3iJzpfqaQh5YRJaFQQgZWHr8rDHUugBSgitiX2Q+l+c1YCyrnSq3XhHeT93q
         K5K4QvfKTbHEOVP3pdlTRN+/TbgKf/sndRMkVmUTcjkUnB+0b6V8ukRvg+1yzWapdLkI
         QS+dWrYCxuiwa+VmBk2LZEFBbaObzLwZJAF9YnM8daRcN/NCyLGuahNjQffAF1S7Aho9
         wKfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dpins7gF;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd43.google.com (mail-io1-xd43.google.com. [2607:f8b0:4864:20::d43])
        by gmr-mx.google.com with ESMTPS id e7si236033pfh.5.2019.07.08.04.04.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Jul 2019 04:04:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43 as permitted sender) client-ip=2607:f8b0:4864:20::d43;
Received: by mail-io1-xd43.google.com with SMTP id m24so24736175ioo.2
        for <kasan-dev@googlegroups.com>; Mon, 08 Jul 2019 04:04:30 -0700 (PDT)
X-Received: by 2002:a5e:c241:: with SMTP id w1mr12333851iop.58.1562583869283;
 Mon, 08 Jul 2019 04:04:29 -0700 (PDT)
MIME-Version: 1.0
References: <20190708004729.GL17490@shao2-debian> <20190708105533.GH3402@hirez.programming.kicks-ass.net>
In-Reply-To: <20190708105533.GH3402@hirez.programming.kicks-ass.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 8 Jul 2019 13:04:18 +0200
Message-ID: <CACT4Y+aJYy-aRCAArTEsTKSz1NPE2JONk68P67qPb=7iun3uwQ@mail.gmail.com>
Subject: Re: 7457c0da02 [ 0.733186] BUG: KASAN: unknown-crash in unwind_next_frame
To: Peter Zijlstra <peterz@infradead.org>
Cc: kernel test robot <rong.a.chen@intel.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, LKP <lkp@01.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dpins7gF;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43
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

On Mon, Jul 8, 2019 at 12:55 PM Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Mon, Jul 08, 2019 at 08:47:29AM +0800, kernel test robot wrote:
> > Greetings,
> >
> > 0day kernel testing robot got the below dmesg and the first bad commit is
> >
> > https://kernel.googlesource.com/pub/scm/linux/kernel/git/next/linux-next.git master
> >
> > commit 7457c0da024b181a9143988d740001f9bc98698d
> > Author:     Peter Zijlstra <peterz@infradead.org>
> > AuthorDate: Fri May 3 12:22:47 2019 +0200
> > Commit:     Ingo Molnar <mingo@kernel.org>
> > CommitDate: Tue Jun 25 10:23:50 2019 +0200
> >
> >     x86/alternatives: Add int3_emulate_call() selftest
> >
> >     Given that the entry_*.S changes for this functionality are somewhat
> >     tricky, make sure the paths are tested every boot, instead of on the
> >     rare occasion when we trip an INT3 while rewriting text.
> >
> >     Requested-by: Andy Lutomirski <luto@kernel.org>
> >     Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> >     Reviewed-by: Josh Poimboeuf <jpoimboe@redhat.com>
> >     Acked-by: Andy Lutomirski <luto@kernel.org>
> >     Cc: Linus Torvalds <torvalds@linux-foundation.org>
> >     Cc: Peter Zijlstra <peterz@infradead.org>
> >     Cc: Thomas Gleixner <tglx@linutronix.de>
> >     Signed-off-by: Ingo Molnar <mingo@kernel.org>
> >
> > faeedb0679  x86/stackframe/32: Allow int3_emulate_push()
> > 7457c0da02  x86/alternatives: Add int3_emulate_call() selftest
> > +-------------------------------------------------------+------------+------------+
> > |                                                       | faeedb0679 | 7457c0da02 |
> > +-------------------------------------------------------+------------+------------+
> > | boot_successes                                        | 33         | 8          |
> > | boot_failures                                         | 2          | 4          |
> > | WARNING:possible_circular_locking_dependency_detected | 2          |            |
> > | BUG:KASAN:unknown-crash_in_u                          | 0          | 4          |
> > +-------------------------------------------------------+------------+------------+
> >
> > If you fix the issue, kindly add following tag
> > Reported-by: kernel test robot <rong.a.chen@intel.com>
> >
> > [    0.726834] CPU: GenuineIntel Intel Core Processor (Haswell) (family: 0x6, model: 0x3c, stepping: 0x1)
> > [    0.728007] Spectre V2 : Spectre mitigation: kernel not compiled with retpoline; no mitigation available!
> > [    0.728009] Speculative Store Bypass: Vulnerable
> > [    0.729969] MDS: Vulnerable: Clear CPU buffers attempted, no microcode
> > [    0.732269] ==================================================================
> > [    0.733186] BUG: KASAN: unknown-crash in unwind_next_frame+0x3f6/0x490
>
> This is a bit of a puzzle; I'm not sure what KASAN is trying to tell us
> here, also isn't the unwinder expected to go off into the weeds at times
> and 'expected' to cope with that? I'm also very much unsure how the
> fingered commit would lead to this, the below splat is in a lockdep
> unwind from completely unrealted code (pageattr).
>
> Josh, Andrey, any clues?

+kasan-dev@googlegroups.com

Frame pointer unwinder is supposed to be precise for the current task,
it should not touch random memory. This is thoroughly tested. If we
start giving up on this property, we will open door for lots of bugs.
Don't know about ORC, I guess it also meant to be precise, but we just
never stressed it.
I don't see what unwinder is involved here.


> > [    0.734146] Read of size 8 at addr ffffffff84007db0 by task swapper/0
> > [    0.734963]
> > [    0.735168] CPU: 0 PID: 0 Comm: swapper Tainted: G                T 5.2.0-rc6-00013-g7457c0d #1
> > [    0.736266] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.10.2-1 04/01/2014
> > [    0.737374] Call Trace:
> > [    0.737697]  dump_stack+0x19/0x1b
> > [    0.738129]  print_address_description+0x1b0/0x2b2
> > [    0.738745]  ? unwind_next_frame+0x3f6/0x490
> > [    0.739370]  __kasan_report+0x10f/0x171
> > [    0.739959]  ? unwind_next_frame+0x3f6/0x490
> > [    0.739959]  kasan_report+0x12/0x1c
> > [    0.739959]  __asan_load8+0x54/0x81
> > [    0.739959]  unwind_next_frame+0x3f6/0x490
> > [    0.739959]  ? unwind_dump+0x24e/0x24e
> > [    0.739959]  unwind_next_frame+0x1b/0x23
> > [    0.739959]  ? create_prof_cpu_mask+0x20/0x20
> > [    0.739959]  arch_stack_walk+0x68/0xa5
> > [    0.739959]  ? set_memory_4k+0x2a/0x2c
> > [    0.739959]  stack_trace_save+0x7b/0xa0
> > [    0.739959]  ? stack_trace_consume_entry+0x89/0x89
> > [    0.739959]  save_trace+0x3c/0x93
> > [    0.739959]  mark_lock+0x1ef/0x9b1
> > [    0.739959]  ? sched_clock_local+0x86/0xa6
> > [    0.739959]  __lock_acquire+0x3ba/0x1bea
> > [    0.739959]  ? __asan_loadN+0xf/0x11
> > [    0.739959]  ? mark_held_locks+0x8e/0x8e
> > [    0.739959]  ? mark_lock+0xb4/0x9b1
> > [    0.739959]  ? sched_clock_local+0x86/0xa6
> > [    0.739959]  lock_acquire+0x122/0x221
> > [    0.739959]  ? _vm_unmap_aliases+0x141/0x183
> > [    0.739959]  __mutex_lock+0xb6/0x731
> > [    0.739959]  ? _vm_unmap_aliases+0x141/0x183
> > [    0.739959]  ? sched_clock_cpu+0xac/0xb1
> > [    0.739959]  ? __mutex_add_waiter+0xae/0xae
> > [    0.739959]  ? lock_downgrade+0x368/0x368
> > [    0.739959]  ? _vm_unmap_aliases+0x40/0x183
> > [    0.739959]  mutex_lock_nested+0x16/0x18
> > [    0.739959]  _vm_unmap_aliases+0x141/0x183
> > [    0.739959]  ? _vm_unmap_aliases+0x40/0x183
> > [    0.739959]  vm_unmap_aliases+0x14/0x16
> > [    0.739959]  change_page_attr_set_clr+0x15e/0x2f2
> > [    0.739959]  ? __set_pages_p+0x111/0x111
> > [    0.739959]  ? alternative_instructions+0xd8/0x118
> > [    0.739959]  ? arch_init_ideal_nops+0x181/0x181
> > [    0.739959]  set_memory_4k+0x2a/0x2c
> > [    0.739959]  check_bugs+0x11fd/0x1298
> > [    0.739959]  ? l1tf_cmdline+0x1dc/0x1dc
> > [    0.739959]  ? proc_create_single_data+0x5f/0x6e
> > [    0.739959]  ? cgroup_init+0x2b1/0x2f6
> > [    0.739959]  start_kernel+0x793/0x7eb
> > [    0.739959]  ? thread_stack_cache_init+0x2e/0x2e
> > [    0.739959]  ? idt_setup_early_handler+0x70/0xb1
> > [    0.739959]  x86_64_start_reservations+0x55/0x76
> > [    0.739959]  x86_64_start_kernel+0x87/0xaa
> > [    0.739959]  secondary_startup_64+0xa4/0xb0
> > [    0.739959]
> > [    0.739959] Memory state around the buggy address:
> > [    0.739959]  ffffffff84007c80: 00 00 00 00 00 00 00 00 00 00 00 00 00 f1 f1 f1
> > [    0.739959]  ffffffff84007d00: f1 00 00 00 00 00 00 00 00 00 f2 f2 f2 f3 f3 f3
> > [    0.739959] >ffffffff84007d80: f3 79 be 52 49 79 be 00 00 00 00 00 00 00 00 f1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaJYy-aRCAArTEsTKSz1NPE2JONk68P67qPb%3D7iun3uwQ%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
