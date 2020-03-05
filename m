Return-Path: <kasan-dev+bncBCMIZB7QWENRBA5NQTZQKGQETEQWG2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6741317A892
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Mar 2020 16:11:01 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id j15sf3173209qvp.21
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2020 07:11:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583421059; cv=pass;
        d=google.com; s=arc-20160816;
        b=a5wA67h2wst69RMKJHgrlOTEY516YF5DTImok/BJVx6/xNYAcf/qq690CNrz3X6Cxe
         UYwm8pdqHhsINZtbWXs2QDA8sxUM+VzSM1CBbMOc90Sx7PrxQuLq4BauL4oZwECY51oZ
         poBxvLsRTrBo3GP4oirTM9vqibLFc8MmIJUeTfb+SJ7MidaxytvrG9TE8Mm/wVIrIdr1
         fQvgxODHib39mB9gqVtFXuKYKzeHl06DUPTu9pgI3npxgvVpa8GAA1t7Tj0atKrcklVt
         lEZDrPX3bOzgsyje5q3KdQD46Ppfc3fSqa8PnajMAtWDXDOG2Do+OJn98mUVkcS0+pnD
         5NUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=POqugngKa4Fpe9tOC8Ux0GjnnxCOyh6tZN0n6VdzOjE=;
        b=CZDPEwpP37VmD+1eMV4rEPjy02IgqxCaa7bLaVJCZRYdqTH1graSKGqdIcHSGprWrY
         CkVEmaPXWuE7JkDj02QwGT9GC5tN8aOjrkePA3WTrWfseMU7yRkeuJ3rrWBjRoQ1cRxY
         rv1gTsnpyYtxVSQiUisodPtBPPx5UPR7BmltwVH5SJmU1LG7xJgVRwg0VsRbOH/SaOMq
         UrQXhrivjGWDe76PweRviDXZVCpjskXlahd92D3eowB2LcLiDJaaL+vtUas/SsGSCAEv
         zcWmEPqXm0v7UJT7MDS7qCwaC9UtlWu8lpB4TEuD3ibK47k8OQxr6v73nz7taqZlhc0I
         h1MQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=h7SoTNr7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=POqugngKa4Fpe9tOC8Ux0GjnnxCOyh6tZN0n6VdzOjE=;
        b=VYtPrsGdTCV3qz7CNIoxY1fsQ1K6UCrnky4K84Irjxk/HanhjK3aKOBV9DdaqWQ/Ma
         CiTp1O0ml+ZPoCmK3VCRegjfRxo9uEmRe+cbIrTIciguWtz43V2QGTyyY4jmpMdEHyZ/
         Tbq0ono/TYVXIPgvm8+cFF/te/ZbXkHpsMnD/w1GCZ7eXhaAM8q79Hig/E3OcubI0K4S
         V8708lKCbIT7nV+EJk/BdlW6NqnaArn7/grNSslJQgw8vVmQV6I02bJaBKJSwENvQwWh
         uPRhk7xjoqb+MGjsdF4bLVH+00cV+GSLPJW+aAqc7UcECJDI5lUG6VwsfenBCvdQ+nLy
         +tkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=POqugngKa4Fpe9tOC8Ux0GjnnxCOyh6tZN0n6VdzOjE=;
        b=ZknXvVaHIc5CNQhbeuEfRs3Z6hH0Yymr7YeuEn4TBnF0uqbTzJtvsrWafxbVGPF3AC
         uhD5QWUB2wiSA7n7sul531tjD3NVWAI3oyNzNnFDP2V9VK3ZBk6XZhGbVixfSvXjCDuV
         Uc7NfAoufeIFOzdqQuFfRGZunHfbMlroz2wktRoPjKmmGrsMNAH5tYsIaY4+DkNkMyjA
         EhEqDkpzYFzsX9eXBXx8zfN0eARskaQc3b0bnaAqdU3mtWVZ9MX/4VMPLwBEfJvmBIiQ
         rSefoT+8koCM8ASLfWND92Ck4eEUzWovlwsOdFds1fcmW7bMv9h04qjVM7JVGwz2Xpkj
         VM/w==
X-Gm-Message-State: ANhLgQ3/+S7Ku1TgrA6OjxM7I43vSTCIZEixK59EIoHboKFmMS3Se+Qv
	mBYQt0fvVixDuaJ9qlR7G/s=
X-Google-Smtp-Source: ADFU+vvPEL04vfiZWGIc7wxEU2gdxP6mLxioZjXIFJuFzFXysJpBdT6IKnjL11rqjii7CupGA6MNrQ==
X-Received: by 2002:a05:6214:10c2:: with SMTP id r2mr2974832qvs.83.1583421059295;
        Thu, 05 Mar 2020 07:10:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:518d:: with SMTP id c13ls1021804qtn.10.gmail; Thu, 05
 Mar 2020 07:10:58 -0800 (PST)
X-Received: by 2002:ac8:6a15:: with SMTP id t21mr7792604qtr.235.1583421058730;
        Thu, 05 Mar 2020 07:10:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583421058; cv=none;
        d=google.com; s=arc-20160816;
        b=foT2REsQZueXEtymQwEC6wUnyy8b0v4bbr17sgX9hKQq8F2ICGX9ar5WhKzs86hcfW
         so9KVjS6set3pNe4wnHzqBHreli4kvfrV6UL4eZraS3z20S3JuQnBjWH7C8VuyqudWzl
         cbtPM4VVJsG+zKR0Gpqcg+WQi8npDGv8giX3y9UTsAprIequhiFcV9blVlhuHoILbDuy
         X8SJkYkHMYQWsGWUtjnFGXoPBUk997AlsmjLsuj7hbEavLOwagCt20YrUvGo0ytUp+71
         IL0rLx/aD9Ag1QKbwxuSKp7k6lWekoseRDd9O27hNLi1fsh15eu+7AKrl67SftrTBSyT
         1EyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Qaiv0cRltBM+7y6wg7RhTH4NDHArX7Wn2hS7NycZZlU=;
        b=cFNhD2hw0f7bqWTUjT5u7oA67omEm/z1/yAn2c17P3cmZKAHDm/DbSNidlUE1Rc5pu
         yduspZuc5K9olYnamUm06CyfZshTS2O0eDx0s7shR0T0c2P9/3KtZzMTvjKFKTm+V9or
         C+v2j4TTLizemAZWr96qYxjKUbonyQ38Wu06x4fPfa3x6qhOv/MzajLNkBUsJqgEtmuN
         AN6qt6HmET4WU+vKOxAKOcJOM03IMgXFaJrD/CNBaq8wUVraK6nzcfGbypij1nHjHslK
         5FbR3dnUVkz8wob4mWAZaGfFe3IWrmXG/gKZlhEsV0uxzE4B8/DpuAE5cGPr5ww3nVO/
         VaYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=h7SoTNr7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id x18si258447qtk.0.2020.03.05.07.10.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Mar 2020 07:10:58 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id m2so5591003qka.7
        for <kasan-dev@googlegroups.com>; Thu, 05 Mar 2020 07:10:58 -0800 (PST)
X-Received: by 2002:a37:664d:: with SMTP id a74mr7978053qkc.256.1583421057744;
 Thu, 05 Mar 2020 07:10:57 -0800 (PST)
MIME-Version: 1.0
References: <202002292221.D4YLxcV6%lkp@intel.com> <20200305134341.GY2596@hirez.programming.kicks-ass.net>
 <CACT4Y+apHDVM7u8f660vc3orkHtCXY+ZGgn_Ueu_eXDxDw3Dgw@mail.gmail.com>
In-Reply-To: <CACT4Y+apHDVM7u8f660vc3orkHtCXY+ZGgn_Ueu_eXDxDw3Dgw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Mar 2020 16:10:46 +0100
Message-ID: <CACT4Y+ZuGLqNaB+C+VJREtOrnTZVyHLckdAHRMSHF3JMDTg_TA@mail.gmail.com>
Subject: Re: [peterz-queue:core/rcu 31/33] arch/x86/kernel/alternative.c:961:26:
 error: inlining failed in call to always_inline 'try_get_desc': function
 attribute mismatch
To: Peter Zijlstra <peterz@infradead.org>
Cc: kbuild test robot <lkp@intel.com>, kbuild-all@lists.01.org, 
	Thomas Gleixner <tglx@linutronix.de>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=h7SoTNr7;       spf=pass
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

On Thu, Mar 5, 2020 at 4:00 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Mar 5, 2020 at 2:43 PM Peter Zijlstra <peterz@infradead.org> wrote:
> >
> >
> > Dmitry; I keep getting this from the 0day robot, but I can't reproduce
> > locally (with GCC-8 and up).
> >
> > The alternative to having that __no_sanitize is moving the code that
> > wants this into it's own .c file and using the Makefile hacks to kills
> > everything dead, but that's cumbersome too.
> >
> > The thing is, Thomas is reworking the x86 entry code and we're moving a
> > whole bunch of that into C, those early entry functions also all want
> > this.
> >
> > Do you have any clues as to what gcc-7 is on about and what, if
> > anything, we can do about this?

What we are asking it to do is impossible to satisfy. For now I am
puzzled as to why gcc-8 does not produce the same warning. I think it
should. So far I can't find any recent relevant changes in gcc code.

> Hi Peter,
>
> I can reproduce this on:
>
> commit 38b47f3cd6f56a0616b0503bbd58c9ab8b3511e9 (HEAD)
>    x86/int3: Ensure that poke_int3_handler() is not sanitized
>
> with a small diff:
>
> --- a/include/linux/rcupdate.h
> +++ b/include/linux/rcupdate.h
> @@ -194,14 +194,14 @@ static inline int trace_rcu_enter(void)
>  {
>         int state = !rcu_is_watching();
>         if (state)
> -               rcu_irq_enter_irqsave();
> +               rcu_irq_enter_irqsafe();
>         return state;
>  }
>
>  static inline void trace_rcu_exit(int state)
>  {
>         if (state)
> -               rcu_irq_exit_irqsave();
> +               rcu_irq_exit_irqsafe();
>  }
>
> by running:
>
> make CC=gcc-7 arch/x86/kernel/alternative.o
> make CC=gcc-8 arch/x86/kernel/alternative.o
>
>
> Question: do we need/want to not kasan-instrument user_mode?
>
>
>
>
>
> > On Sat, Feb 29, 2020 at 10:37:26PM +0800, kbuild test robot wrote:
> > > tree:   https://git.kernel.org/pub/scm/linux/kernel/git/peterz/queue.git core/rcu
> > > head:   bc72cd8dac4be9572f0cae33b096f9c23460e08a
> > > commit: 2834aaec9e68691ed8d74bdfd3bbea47b6b3972f [31/33] x86/int3: Ensure that poke_int3_handler() is not sanitized
> > > config: x86_64-allmodconfig (attached as .config)
> > > compiler: gcc-7 (Debian 7.5.0-5) 7.5.0
> > > reproduce:
> > >         git checkout 2834aaec9e68691ed8d74bdfd3bbea47b6b3972f
> > >         # save the attached .config to linux build tree
> > >         make ARCH=x86_64
> > >
> > > If you fix the issue, kindly add following tag
> > > Reported-by: kbuild test robot <lkp@intel.com>
> > >
> > > All errors (new ones prefixed by >>):
> > >
> > >    In file included from arch/x86/include/asm/math_emu.h:5:0,
> > >                     from arch/x86/include/asm/processor.h:13,
> > >                     from arch/x86/include/asm/cpufeature.h:5,
> > >                     from arch/x86/include/asm/thread_info.h:53,
> > >                     from include/linux/thread_info.h:38,
> > >                     from arch/x86/include/asm/preempt.h:7,
> > >                     from include/linux/preempt.h:78,
> > >                     from include/linux/spinlock.h:51,
> > >                     from include/linux/seqlock.h:36,
> > >                     from include/linux/time.h:6,
> > >                     from include/linux/stat.h:19,
> > >                     from include/linux/module.h:13,
> > >                     from arch/x86/kernel/alternative.c:4:
> > >    arch/x86/kernel/alternative.c: In function 'poke_int3_handler':
> > >    arch/x86/include/asm/ptrace.h:126:28: error: inlining failed in call to always_inline 'user_mode': function attribute mismatch
> > >     static __always_inline int user_mode(struct pt_regs *regs)
> > >                                ^~~~~~~~~
> > >    arch/x86/kernel/alternative.c:1000:6: note: called from here
> > >      if (user_mode(regs))
> > >          ^~~~~~~~~~~~~~~
> > > >> arch/x86/kernel/alternative.c:961:26: error: inlining failed in call to always_inline 'try_get_desc': function attribute mismatch
> > >     struct bp_patching_desc *try_get_desc(struct bp_patching_desc **descp)
> > >                              ^~~~~~~~~~~~
> > >    arch/x86/kernel/alternative.c:1013:7: note: called from here
> > >      desc = try_get_desc(&bp_desc);
> > >      ~~~~~^~~~~~~~~~~~~~~~~~~~~~~~
> > >    In file included from arch/x86/kernel/alternative.c:17:0:
> > > >> include/linux/bsearch.h:8:7: error: inlining failed in call to always_inline '__bsearch': function attribute mismatch
> > >     void *__bsearch(const void *key, const void *base, size_t num, size_t size, cmp_func_t cmp)
> > >           ^~~~~~~~~
> > >    arch/x86/kernel/alternative.c:1026:6: note: called from here
> > >       tp = __bsearch(ip, desc->vec, desc->nr_entries,
> > >       ~~~^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > >               sizeof(struct text_poke_loc),
> > >               ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > >               patch_cmp);
> > >               ~~~~~~~~~~
> > >    arch/x86/kernel/alternative.c:977:30: error: inlining failed in call to always_inline 'text_poke_addr': function attribute mismatch
> > >     static __always_inline void *text_poke_addr(struct text_poke_loc *tp)
> > >                                  ^~~~~~~~~~~~~~
> > >    arch/x86/kernel/alternative.c:1033:7: note: called from here
> > >       if (text_poke_addr(tp) != ip)
> > >           ^~~~~~~~~~~~~~~~~~
> > >    In file included from arch/x86/include/asm/kprobes.h:18:0,
> > >                     from include/linux/kprobes.h:30,
> > >                     from arch/x86/kernel/alternative.c:15:
> > > >> arch/x86/include/asm/text-patching.h:67:28: error: inlining failed in call to always_inline 'text_opcode_size': function attribute mismatch
> > >     static __always_inline int text_opcode_size(u8 opcode)
> > >                                ^~~~~~~~~~~~~~~~
> > >    arch/x86/kernel/alternative.c:1037:6: note: called from here
> > >      len = text_opcode_size(tp->opcode);
> > >      ~~~~^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > >    In file included from arch/x86/include/asm/kprobes.h:18:0,
> > >                     from include/linux/kprobes.h:30,
> > >                     from arch/x86/kernel/alternative.c:15:
> > > >> arch/x86/include/asm/text-patching.h:144:6: error: inlining failed in call to always_inline 'int3_emulate_call': function attribute mismatch
> > >     void int3_emulate_call(struct pt_regs *regs, unsigned long func)
> > >          ^~~~~~~~~~~~~~~~~
> > >    arch/x86/kernel/alternative.c:1049:3: note: called from here
> > >       int3_emulate_call(regs, (long)ip + tp->rel32);
> > >       ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > >    In file included from arch/x86/include/asm/kprobes.h:18:0,
> > >                     from include/linux/kprobes.h:30,
> > >                     from arch/x86/kernel/alternative.c:15:
> > > >> arch/x86/include/asm/text-patching.h:122:6: error: inlining failed in call to always_inline 'int3_emulate_jmp': function attribute mismatch
> > >     void int3_emulate_jmp(struct pt_regs *regs, unsigned long ip)
> > >          ^~~~~~~~~~~~~~~~
> > >    arch/x86/kernel/alternative.c:1054:3: note: called from here
> > >       int3_emulate_jmp(regs, (long)ip + tp->rel32);
> > >       ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > > >> arch/x86/kernel/alternative.c:971:29: error: inlining failed in call to always_inline 'put_desc': function attribute mismatch
> > >     static __always_inline void put_desc(struct bp_patching_desc *desc)
> > >                                 ^~~~~~~~
> > >    arch/x86/kernel/alternative.c:1064:2: note: called from here
> > >      put_desc(desc);
> > >      ^~~~~~~~~~~~~~
> > > --
> > >    In file included from include/linux/preempt.h:78:0,
> > >                     from include/linux/rcupdate.h:27,
> > >                     from include/linux/rculist.h:11,
> > >                     from include/linux/pid.h:5,
> > >                     from include/linux/sched.h:14,
> > >                     from include/linux/context_tracking.h:5,
> > >                     from arch/x86/kernel/traps.c:15:
> > >    arch/x86/kernel/traps.c: In function 'do_int3':
> > > >> arch/x86/include/asm/preempt.h:24:28: error: inlining failed in call to always_inline 'preempt_count': function attribute mismatch
> > >     static __always_inline int preempt_count(void)
> > >                                ^~~~~~~~~~~~~
> > >    In file included from arch/x86/include/asm/current.h:5:0,
> > >                     from include/linux/sched.h:12,
> > >                     from include/linux/context_tracking.h:5,
> > >                     from arch/x86/kernel/traps.c:15:
> > >    include/linux/preempt.h:102:20: note: called from here
> > >     #define in_nmi()  (preempt_count() & NMI_MASK)
> > >                        ^~~~~~~~~~~~~~~
> > >    include/linux/compiler.h:78:42: note: in definition of macro 'unlikely'
> > >     # define unlikely(x) __builtin_expect(!!(x), 0)
> > >                                              ^
> > >    include/linux/hardirq.h:86:3: note: in expansion of macro 'BUG_ON'
> > >       BUG_ON(in_nmi() == NMI_MASK);   \
> > >       ^~~~~~
> > >    include/linux/hardirq.h:86:10: note: in expansion of macro 'in_nmi'
> > >       BUG_ON(in_nmi() == NMI_MASK);   \
> > >              ^~~~~~
> > >    arch/x86/kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> > >      nmi_enter();
> > >      ^~~~~~~~~
> > >    In file included from include/linux/hardirq.h:7:0,
> > >                     from include/linux/interrupt.h:11,
> > >                     from arch/x86/kernel/traps.c:16:
> > > >> include/linux/ftrace_irq.h:10:29: error: inlining failed in call to always_inline 'ftrace_nmi_enter': function attribute mismatch
> > >     static __always_inline void ftrace_nmi_enter(void)
> > >                                 ^~~~~~~~~~~~~~~~
> > >    In file included from include/linux/interrupt.h:11:0,
> > >                     from arch/x86/kernel/traps.c:16:
> > >    include/linux/hardirq.h:85:3: note: called from here
> > >       ftrace_nmi_enter();    \
> > >       ^~~~~~~~~~~~~~~~~~
> > >    arch/x86/kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> > >      nmi_enter();
> > >      ^~~~~~~~~
> > >    In file included from include/linux/sched.h:12:0,
> > >                     from include/linux/context_tracking.h:5,
> > >                     from arch/x86/kernel/traps.c:15:
> > > >> arch/x86/include/asm/current.h:13:44: error: inlining failed in call to always_inline 'get_current': function attribute mismatch
> > >     static __always_inline struct task_struct *get_current(void)
> > >                                                ^~~~~~~~~~~
> > >    arch/x86/include/asm/current.h:18:17: note: called from here
> > >     #define current get_current()
> > >                     ^~~~~~~~~~~~~
> > >    include/linux/lockdep.h:304:2: note: in expansion of macro 'current'
> > >      current->lockdep_recursion += LOCKDEP_OFF; \
> > >      ^~~~~~~
> > >    include/linux/hardirq.h:84:3: note: in expansion of macro 'lockdep_off'
> > >       lockdep_off();     \
> > >       ^~~~~~~~~~~
> > >    arch/x86/kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> > >      nmi_enter();
> > >      ^~~~~~~~~
> > > >> arch/x86/include/asm/current.h:13:44: error: inlining failed in call to always_inline 'get_current': function attribute mismatch
> > >     static __always_inline struct task_struct *get_current(void)
> > >                                                ^~~~~~~~~~~
> > >    arch/x86/include/asm/current.h:18:17: note: called from here
> > >     #define current get_current()
> > >                     ^~~~~~~~~~~~~
> > >    include/linux/irqflags.h:40:2: note: in expansion of macro 'current'
> > >      current->hardirq_context++;  \
> > >      ^~~~~~~
> > >    include/linux/hardirq.h:89:3: note: in expansion of macro 'trace_hardirq_enter'
> > >       trace_hardirq_enter();    \
> > >       ^~~~~~~~~~~~~~~~~~~
> > >    arch/x86/kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> > >      nmi_enter();
> > >      ^~~~~~~~~
> > >    In file included from include/linux/preempt.h:78:0,
> > >                     from include/linux/rcupdate.h:27,
> > >                     from include/linux/rculist.h:11,
> > >                     from include/linux/pid.h:5,
> > >                     from include/linux/sched.h:14,
> > >                     from include/linux/context_tracking.h:5,
> > >                     from arch/x86/kernel/traps.c:15:
> > >    arch/x86/include/asm/preempt.h:77:29: error: inlining failed in call to always_inline '__preempt_count_add': function attribute mismatch
> > >     static __always_inline void __preempt_count_add(int val)
> > >                                 ^~~~~~~~~~~~~~~~~~~
> > >    In file included from include/linux/interrupt.h:11:0,
> > >                     from arch/x86/kernel/traps.c:16:
> > >    include/linux/hardirq.h:87:3: note: called from here
> > >       __preempt_count_add(NMI_OFFSET + HARDIRQ_OFFSET); \
> > >       ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > >    arch/x86/kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> > >      nmi_enter();
> > >      ^~~~~~~~~
> > >    In file included from include/linux/preempt.h:78:0,
> > >                     from include/linux/rcupdate.h:27,
> > >                     from include/linux/rculist.h:11,
> > >                     from include/linux/pid.h:5,
> > >                     from include/linux/sched.h:14,
> > >                     from include/linux/context_tracking.h:5,
> > >                     from arch/x86/kernel/traps.c:15:
> > > >> arch/x86/include/asm/preempt.h:24:28: error: inlining failed in call to always_inline 'preempt_count': function attribute mismatch
> > >     static __always_inline int preempt_count(void)
> > >                                ^~~~~~~~~~~~~
> > >    In file included from arch/x86/include/asm/current.h:5:0,
> > >                     from include/linux/sched.h:12,
> > >                     from include/linux/context_tracking.h:5,
> > >                     from arch/x86/kernel/traps.c:15:
> > >    include/linux/preempt.h:102:20: note: called from here
> > >     #define in_nmi()  (preempt_count() & NMI_MASK)
> > >                        ^~~~~~~~~~~~~~~
> > >    include/linux/compiler.h:78:42: note: in definition of macro 'unlikely'
> > >     # define unlikely(x) __builtin_expect(!!(x), 0)
> > >                                              ^
> > >    include/linux/hardirq.h:96:3: note: in expansion of macro 'BUG_ON'
> > >       BUG_ON(!in_nmi());    \
> > >       ^~~~~~
> > >    include/linux/hardirq.h:96:11: note: in expansion of macro 'in_nmi'
> > >       BUG_ON(!in_nmi());    \
> > >               ^~~~~~
> > >    arch/x86/kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> > >      nmi_exit();
> > >      ^~~~~~~~
> > >    In file included from include/linux/sched.h:12:0,
> > >                     from include/linux/context_tracking.h:5,
> > >                     from arch/x86/kernel/traps.c:15:
> > > >> arch/x86/include/asm/current.h:13:44: error: inlining failed in call to always_inline 'get_current': function attribute mismatch
> > >     static __always_inline struct task_struct *get_current(void)
> > >                                                ^~~~~~~~~~~
> > >    arch/x86/include/asm/current.h:18:17: note: called from here
> > >     #define current get_current()
> > >                     ^~~~~~~~~~~~~
> > >    include/linux/irqflags.h:44:2: note: in expansion of macro 'current'
> > >      current->hardirq_context--;  \
> > >      ^~~~~~~
> > >    include/linux/hardirq.h:94:3: note: in expansion of macro 'trace_hardirq_exit'
> > >       trace_hardirq_exit();    \
> > >       ^~~~~~~~~~~~~~~~~~
> > >    arch/x86/kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> > >      nmi_exit();
> > >      ^~~~~~~~
> > > >> arch/x86/include/asm/current.h:13:44: error: inlining failed in call to always_inline 'get_current': function attribute mismatch
> > >     static __always_inline struct task_struct *get_current(void)
> > >                                                ^~~~~~~~~~~
> > >    arch/x86/include/asm/current.h:18:17: note: called from here
> > >     #define current get_current()
> > >                     ^~~~~~~~~~~~~
> > >    include/linux/lockdep.h:309:2: note: in expansion of macro 'current'
> > >      current->lockdep_recursion -= LOCKDEP_OFF; \
> > >      ^~~~~~~
> > >    include/linux/hardirq.h:99:3: note: in expansion of macro 'lockdep_on'
> > >       lockdep_on();     \
> > >       ^~~~~~~~~~
> > >    arch/x86/kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> > >      nmi_exit();
> > >      ^~~~~~~~
> > >    In file included from include/linux/hardirq.h:7:0,
> > >                     from include/linux/interrupt.h:11,
> > >                     from arch/x86/kernel/traps.c:16:
> > > >> include/linux/ftrace_irq.h:18:29: error: inlining failed in call to always_inline 'ftrace_nmi_exit': function attribute mismatch
> > >     static __always_inline void ftrace_nmi_exit(void)
> > >                                 ^~~~~~~~~~~~~~~
> > >    In file included from include/linux/interrupt.h:11:0,
> > >                     from arch/x86/kernel/traps.c:16:
> > >    include/linux/hardirq.h:98:3: note: called from here
> > >       ftrace_nmi_exit();    \
> > >       ^~~~~~~~~~~~~~~~~
> > >    arch/x86/kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> > >      nmi_exit();
> > >      ^~~~~~~~
> > >    In file included from include/linux/preempt.h:78:0,
> > >                     from include/linux/rcupdate.h:27,
> > >                     from include/linux/rculist.h:11,
> > >                     from include/linux/pid.h:5,
> > >                     from include/linux/sched.h:14,
> > >                     from include/linux/context_tracking.h:5,
> > >                     from arch/x86/kernel/traps.c:15:
> > >    arch/x86/include/asm/preempt.h:82:29: error: inlining failed in call to always_inline '__preempt_count_sub': function attribute mismatch
> > >     static __always_inline void __preempt_count_sub(int val)
> > >                                 ^~~~~~~~~~~~~~~~~~~
> > >    In file included from include/linux/interrupt.h:11:0,
> > >                     from arch/x86/kernel/traps.c:16:
> > >    include/linux/hardirq.h:97:3: note: called from here
> > >       __preempt_count_sub(NMI_OFFSET + HARDIRQ_OFFSET); \
> > >       ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > >    arch/x86/kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> > >      nmi_exit();
> > >      ^~~~~~~~
> > > --
> > >    In file included from include/linux/preempt.h:78:0,
> > >                     from include/linux/rcupdate.h:27,
> > >                     from include/linux/rculist.h:11,
> > >                     from include/linux/pid.h:5,
> > >                     from include/linux/sched.h:14,
> > >                     from include/linux/context_tracking.h:5,
> > >                     from arch/x86//kernel/traps.c:15:
> > >    arch/x86//kernel/traps.c: In function 'do_int3':
> > > >> arch/x86/include/asm/preempt.h:24:28: error: inlining failed in call to always_inline 'preempt_count': function attribute mismatch
> > >     static __always_inline int preempt_count(void)
> > >                                ^~~~~~~~~~~~~
> > >    In file included from arch/x86/include/asm/current.h:5:0,
> > >                     from include/linux/sched.h:12,
> > >                     from include/linux/context_tracking.h:5,
> > >                     from arch/x86//kernel/traps.c:15:
> > >    include/linux/preempt.h:102:20: note: called from here
> > >     #define in_nmi()  (preempt_count() & NMI_MASK)
> > >                        ^~~~~~~~~~~~~~~
> > >    include/linux/compiler.h:78:42: note: in definition of macro 'unlikely'
> > >     # define unlikely(x) __builtin_expect(!!(x), 0)
> > >                                              ^
> > >    include/linux/hardirq.h:86:3: note: in expansion of macro 'BUG_ON'
> > >       BUG_ON(in_nmi() == NMI_MASK);   \
> > >       ^~~~~~
> > >    include/linux/hardirq.h:86:10: note: in expansion of macro 'in_nmi'
> > >       BUG_ON(in_nmi() == NMI_MASK);   \
> > >              ^~~~~~
> > >    arch/x86//kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> > >      nmi_enter();
> > >      ^~~~~~~~~
> > >    In file included from include/linux/hardirq.h:7:0,
> > >                     from include/linux/interrupt.h:11,
> > >                     from arch/x86//kernel/traps.c:16:
> > > >> include/linux/ftrace_irq.h:10:29: error: inlining failed in call to always_inline 'ftrace_nmi_enter': function attribute mismatch
> > >     static __always_inline void ftrace_nmi_enter(void)
> > >                                 ^~~~~~~~~~~~~~~~
> > >    In file included from include/linux/interrupt.h:11:0,
> > >                     from arch/x86//kernel/traps.c:16:
> > >    include/linux/hardirq.h:85:3: note: called from here
> > >       ftrace_nmi_enter();    \
> > >       ^~~~~~~~~~~~~~~~~~
> > >    arch/x86//kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> > >      nmi_enter();
> > >      ^~~~~~~~~
> > >    In file included from include/linux/sched.h:12:0,
> > >                     from include/linux/context_tracking.h:5,
> > >                     from arch/x86//kernel/traps.c:15:
> > > >> arch/x86/include/asm/current.h:13:44: error: inlining failed in call to always_inline 'get_current': function attribute mismatch
> > >     static __always_inline struct task_struct *get_current(void)
> > >                                                ^~~~~~~~~~~
> > >    arch/x86/include/asm/current.h:18:17: note: called from here
> > >     #define current get_current()
> > >                     ^~~~~~~~~~~~~
> > >    include/linux/lockdep.h:304:2: note: in expansion of macro 'current'
> > >      current->lockdep_recursion += LOCKDEP_OFF; \
> > >      ^~~~~~~
> > >    include/linux/hardirq.h:84:3: note: in expansion of macro 'lockdep_off'
> > >       lockdep_off();     \
> > >       ^~~~~~~~~~~
> > >    arch/x86//kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> > >      nmi_enter();
> > >      ^~~~~~~~~
> > > >> arch/x86/include/asm/current.h:13:44: error: inlining failed in call to always_inline 'get_current': function attribute mismatch
> > >     static __always_inline struct task_struct *get_current(void)
> > >                                                ^~~~~~~~~~~
> > >    arch/x86/include/asm/current.h:18:17: note: called from here
> > >     #define current get_current()
> > >                     ^~~~~~~~~~~~~
> > >    include/linux/irqflags.h:40:2: note: in expansion of macro 'current'
> > >      current->hardirq_context++;  \
> > >      ^~~~~~~
> > >    include/linux/hardirq.h:89:3: note: in expansion of macro 'trace_hardirq_enter'
> > >       trace_hardirq_enter();    \
> > >       ^~~~~~~~~~~~~~~~~~~
> > >    arch/x86//kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> > >      nmi_enter();
> > >      ^~~~~~~~~
> > >    In file included from include/linux/preempt.h:78:0,
> > >                     from include/linux/rcupdate.h:27,
> > >                     from include/linux/rculist.h:11,
> > >                     from include/linux/pid.h:5,
> > >                     from include/linux/sched.h:14,
> > >                     from include/linux/context_tracking.h:5,
> > >                     from arch/x86//kernel/traps.c:15:
> > >    arch/x86/include/asm/preempt.h:77:29: error: inlining failed in call to always_inline '__preempt_count_add': function attribute mismatch
> > >     static __always_inline void __preempt_count_add(int val)
> > >                                 ^~~~~~~~~~~~~~~~~~~
> > >    In file included from include/linux/interrupt.h:11:0,
> > >                     from arch/x86//kernel/traps.c:16:
> > >    include/linux/hardirq.h:87:3: note: called from here
> > >       __preempt_count_add(NMI_OFFSET + HARDIRQ_OFFSET); \
> > >       ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > >    arch/x86//kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> > >      nmi_enter();
> > >      ^~~~~~~~~
> > >    In file included from include/linux/preempt.h:78:0,
> > >                     from include/linux/rcupdate.h:27,
> > >                     from include/linux/rculist.h:11,
> > >                     from include/linux/pid.h:5,
> > >                     from include/linux/sched.h:14,
> > >                     from include/linux/context_tracking.h:5,
> > >                     from arch/x86//kernel/traps.c:15:
> > > >> arch/x86/include/asm/preempt.h:24:28: error: inlining failed in call to always_inline 'preempt_count': function attribute mismatch
> > >     static __always_inline int preempt_count(void)
> > >                                ^~~~~~~~~~~~~
> > >    In file included from arch/x86/include/asm/current.h:5:0,
> > >                     from include/linux/sched.h:12,
> > >                     from include/linux/context_tracking.h:5,
> > >                     from arch/x86//kernel/traps.c:15:
> > >    include/linux/preempt.h:102:20: note: called from here
> > >     #define in_nmi()  (preempt_count() & NMI_MASK)
> > >                        ^~~~~~~~~~~~~~~
> > >    include/linux/compiler.h:78:42: note: in definition of macro 'unlikely'
> > >     # define unlikely(x) __builtin_expect(!!(x), 0)
> > >                                              ^
> > >    include/linux/hardirq.h:96:3: note: in expansion of macro 'BUG_ON'
> > >       BUG_ON(!in_nmi());    \
> > >       ^~~~~~
> > >    include/linux/hardirq.h:96:11: note: in expansion of macro 'in_nmi'
> > >       BUG_ON(!in_nmi());    \
> > >               ^~~~~~
> > >    arch/x86//kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> > >      nmi_exit();
> > >      ^~~~~~~~
> > >    In file included from include/linux/sched.h:12:0,
> > >                     from include/linux/context_tracking.h:5,
> > >                     from arch/x86//kernel/traps.c:15:
> > > >> arch/x86/include/asm/current.h:13:44: error: inlining failed in call to always_inline 'get_current': function attribute mismatch
> > >     static __always_inline struct task_struct *get_current(void)
> > >                                                ^~~~~~~~~~~
> > >    arch/x86/include/asm/current.h:18:17: note: called from here
> > >     #define current get_current()
> > >                     ^~~~~~~~~~~~~
> > >    include/linux/irqflags.h:44:2: note: in expansion of macro 'current'
> > >      current->hardirq_context--;  \
> > >      ^~~~~~~
> > >    include/linux/hardirq.h:94:3: note: in expansion of macro 'trace_hardirq_exit'
> > >       trace_hardirq_exit();    \
> > >       ^~~~~~~~~~~~~~~~~~
> > >    arch/x86//kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> > >      nmi_exit();
> > >      ^~~~~~~~
> > > >> arch/x86/include/asm/current.h:13:44: error: inlining failed in call to always_inline 'get_current': function attribute mismatch
> > >     static __always_inline struct task_struct *get_current(void)
> > >                                                ^~~~~~~~~~~
> > >    arch/x86/include/asm/current.h:18:17: note: called from here
> > >     #define current get_current()
> > >                     ^~~~~~~~~~~~~
> > >    include/linux/lockdep.h:309:2: note: in expansion of macro 'current'
> > >      current->lockdep_recursion -= LOCKDEP_OFF; \
> > >      ^~~~~~~
> > >    include/linux/hardirq.h:99:3: note: in expansion of macro 'lockdep_on'
> > >       lockdep_on();     \
> > >       ^~~~~~~~~~
> > >    arch/x86//kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> > >      nmi_exit();
> > >      ^~~~~~~~
> > >    In file included from include/linux/hardirq.h:7:0,
> > >                     from include/linux/interrupt.h:11,
> > >                     from arch/x86//kernel/traps.c:16:
> > > >> include/linux/ftrace_irq.h:18:29: error: inlining failed in call to always_inline 'ftrace_nmi_exit': function attribute mismatch
> > >     static __always_inline void ftrace_nmi_exit(void)
> > >                                 ^~~~~~~~~~~~~~~
> > >    In file included from include/linux/interrupt.h:11:0,
> > >                     from arch/x86//kernel/traps.c:16:
> > >    include/linux/hardirq.h:98:3: note: called from here
> > >       ftrace_nmi_exit();    \
> > >       ^~~~~~~~~~~~~~~~~
> > >    arch/x86//kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> > >      nmi_exit();
> > >      ^~~~~~~~
> > >    In file included from include/linux/preempt.h:78:0,
> > >                     from include/linux/rcupdate.h:27,
> > >                     from include/linux/rculist.h:11,
> > >                     from include/linux/pid.h:5,
> > >                     from include/linux/sched.h:14,
> > >                     from include/linux/context_tracking.h:5,
> > >                     from arch/x86//kernel/traps.c:15:
> > >    arch/x86/include/asm/preempt.h:82:29: error: inlining failed in call to always_inline '__preempt_count_sub': function attribute mismatch
> > >     static __always_inline void __preempt_count_sub(int val)
> > >                                 ^~~~~~~~~~~~~~~~~~~
> > >    In file included from include/linux/interrupt.h:11:0,
> > >                     from arch/x86//kernel/traps.c:16:
> > >    include/linux/hardirq.h:97:3: note: called from here
> > >       __preempt_count_sub(NMI_OFFSET + HARDIRQ_OFFSET); \
> > >       ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > >    arch/x86//kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> > >      nmi_exit();
> > >      ^~~~~~~~
> > > ..
> > >
> > > vim +/try_get_desc +961 arch/x86/kernel/alternative.c
> > >
> > > 1f676247f36a4b Peter Zijlstra             2019-12-11  959
> > > 809106a6157bce Thomas Gleixner            2020-01-21  960  static __always_inline
> > > 809106a6157bce Thomas Gleixner            2020-01-21 @961  struct bp_patching_desc *try_get_desc(struct bp_patching_desc **descp)
> > > 1f676247f36a4b Peter Zijlstra             2019-12-11  962  {
> > > a9d380bd4091e7 Peter Zijlstra             2020-01-24  963     struct bp_patching_desc *desc = READ_ONCE_NOCHECK(*descp); /* rcu_dereference */
> > > 1f676247f36a4b Peter Zijlstra             2019-12-11  964
> > > a9d380bd4091e7 Peter Zijlstra             2020-01-24  965     if (!desc || !arch_atomic_inc_not_zero(&desc->refs))
> > > 1f676247f36a4b Peter Zijlstra             2019-12-11  966             return NULL;
> > > 1f676247f36a4b Peter Zijlstra             2019-12-11  967
> > > 1f676247f36a4b Peter Zijlstra             2019-12-11  968     return desc;
> > > 1f676247f36a4b Peter Zijlstra             2019-12-11  969  }
> > > 1f676247f36a4b Peter Zijlstra             2019-12-11  970
> > > 809106a6157bce Thomas Gleixner            2020-01-21 @971  static __always_inline void put_desc(struct bp_patching_desc *desc)
> > > 1f676247f36a4b Peter Zijlstra             2019-12-11  972  {
> > > 1f676247f36a4b Peter Zijlstra             2019-12-11  973     smp_mb__before_atomic();
> > > a9d380bd4091e7 Peter Zijlstra             2020-01-24  974     arch_atomic_dec(&desc->refs);
> > > 1f676247f36a4b Peter Zijlstra             2019-12-11  975  }
> > > c0213b0ac03cf6 Daniel Bristot de Oliveira 2019-06-12  976
> > >
> > > :::::: The code at line 961 was first introduced by commit
> > > :::::: 809106a6157bce0fff76bfc7864e7ce34080abe0 x86/int3: Ensure that poke_int3_handler() is not traced
> > >
> > > :::::: TO: Thomas Gleixner <tglx@linutronix.de>
> > > :::::: CC: Peter Zijlstra <peterz@infradead.org>
> > >
> > > ---
> > > 0-DAY CI Kernel Test Service, Intel Corporation
> > > https://lists.01.org/hyperkitty/list/kbuild-all@lists.01.org
> >
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZuGLqNaB%2BC%2BVJREtOrnTZVyHLckdAHRMSHF3JMDTg_TA%40mail.gmail.com.
