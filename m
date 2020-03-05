Return-Path: <kasan-dev+bncBCMIZB7QWENRBKVIQTZQKGQESUKAXNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E26017A85E
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Mar 2020 16:00:59 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id c127sf2112214vkh.18
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2020 07:00:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583420458; cv=pass;
        d=google.com; s=arc-20160816;
        b=RD3jhtd2gdOfGvfNWukq0nURx9JDV33m1ilPu1dmRGPr4P2icrS2gOpt/HwDqCQ9Jp
         eaXg0LwVgC362zTd6LdKE+PqUfL46U7gR7JrNlymN+R0NxW9B/yirONSLu4JEIHygyjw
         Vz1uqp/Pl04hcLSZZHCNCMyKaLcDyNDCVmZHW590gaanxSrFHe60YByz3yjSSy7XK6dQ
         Ep18RP0no0MkYy19wjxvlcBfsa3yo1VbkJkwP6EH1IBN+QN4xR+AYl7xkCr+/C22x21q
         k2jMcXuL1K2TFx4xuJywJasQ0qUdGSLvNcQ0G5W0M8mHA2X4W0nFs3bjWXcK+OPCxg+5
         nPmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Xpccqe7AsfEiMTtSRdFc/8FeJa/3rIsSUnUfEkFnTsU=;
        b=UTm3cUgaxkvPKe4PsWay8GPEmN7C0GKX41S9/qfBfxvOGxDX+x7bFAsPFHiPuXZW2r
         J7ps4BbxYeX0hIRkLaEcN1+mCsx0R3t8FLMGRhFlmOHtl7+v3iebn3TUEcCGGD0TpsYe
         yH6P/UjzXyENVAA0pw4GIRwzpFYkFpL4H7UZJM4+wEpJSasG3tb2X8DOWyYUZsaur1QY
         Nq32e4sYJz2THiSCtHTDUZUs1pWlSp9qpupA17yNGS6ClPLLGvUsYsbnKMkiJQ+s/mDd
         x5U7rW7nZvk48ZYr4iPj/nsr5eS5y5gNnhaUCZG3GjK3g3xHoRLyXp9MR6pN6/+8Zw9p
         bMIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ex8G2A6+;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xpccqe7AsfEiMTtSRdFc/8FeJa/3rIsSUnUfEkFnTsU=;
        b=eqpi4B9gixaexYxidMWSV5MhE87U3ExiBqPqhQWtaRA/OoFLJh+kp+3P0Ibvnk+Npc
         4qttCk4inL5ayJMyIKfkUTxhBy4dz2ry/LBdhwSjNSMghQW7tPx9VzOYLP1g3E6wb1l8
         bR9C+8HBTtSIkEr6e99+hHMAEE5xaYv1QF0Wy/g7mjGEnV31Mf9mDDokiCb1AE2MyrjG
         G6C/Ky2J3eUs4ccF8bQXb8UWJshi6msxKNygrWB1WQ466fEh/kF/QybJJKkKvdwYOoGW
         WqQTiqKYDeanhDz9+l3a4eRhaTimDUYX8K1q8IboIkoWj2U623QRlRhEW43tZK3YcAJ2
         2ffA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xpccqe7AsfEiMTtSRdFc/8FeJa/3rIsSUnUfEkFnTsU=;
        b=KAhzCP5R8tvXsc3AKCoOQ3R9xLyx/2/Af5oBXKAnkRiVFe+lotylew8y5xDRr9hNHb
         l5HUI9njJWNjAj9WIG+UloVJVJiXqyffms1n7wXy68Etds9EJPJ9v618Ot+iXO6JOzAs
         AHzZ1mI9iVpgCYDaBrYKH0iByySeMGfNyGGpljOA+bPuqGrFaVbwFfWsviUXexPnDT4B
         Jvni2PxixEyFHgPYCfpbk5ywd/RGOIZMX9rJglnVDsU59i+Fi9l8TUM1kNhb88TfEaUk
         KxZIG2MqXJbZSwz5TlQPB24vIszr/d9zbFz0Esw+G52UnN+VjQCHzz6xf2cCK91EPT6q
         1hng==
X-Gm-Message-State: ANhLgQ3yciDlEYN5HK7E184CV/hu6Huf14StdGH673msWoRvvultUR79
	/o7HR8f5N5C3Wi3ZegyqIbk=
X-Google-Smtp-Source: ADFU+vvO+3suHZPS90b+pPZTnzWvEANUwb1oub2iIfYsS3HtDROkxqzu53VSxTuFgAvGAbCATXCiWQ==
X-Received: by 2002:a67:8c44:: with SMTP id o65mr5266395vsd.181.1583420458349;
        Thu, 05 Mar 2020 07:00:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:751a:: with SMTP id m26ls54475uap.11.gmail; Thu, 05 Mar
 2020 07:00:57 -0800 (PST)
X-Received: by 2002:a9f:21aa:: with SMTP id 39mr4790842uac.138.1583420457894;
        Thu, 05 Mar 2020 07:00:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583420457; cv=none;
        d=google.com; s=arc-20160816;
        b=wBCT1Q0a9TsWFtE1Fj//7stzCEa34Z3UX4wfz6AsBlsX0RpIYS0uhdRNVYZP4fMOrn
         /QJWcnCxaSNGNNvCailJsLjjW+1UDYet7jwReBICMsmPwvKewqxDG87epqCgTFg9cwbD
         t8rOiAkZorUNtjKyLHhIsKpjmjWQz8vaO3UcvsT2Je6yNb3hsgxQYztIr1m55hg54SPO
         a7QaaiqsgMHug38YuLuhRrxShnQQUxbZ6qy8GahjPGY68i+nT72QJtjKEB5NaEQwv7dO
         +8Q8ZPME2uRtYkZETTnwZ4JBd6O37R6JxomQEatPbG/XhK4Y7I7dSO9Ll2D8fo3wZJrL
         Yz0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pW1XsXMlKF0mwYd8TUNT+Rz9xBvx6M7XY+U2Node5Ok=;
        b=kR9crbzKjFheNqzJQYDt5sf80OV6W8qeNniEUNOOSJcMjNS2COi6ibkQ39Ym+TadZi
         glJwiGmwW6kS35Ojikvy12ITeis4sksvN0R+5VItXmJ01kfQDH19dLkErP73C/nYLaf3
         XpxufT1Wyz4KlIHb/7Ts75s9YF1YY/IXDIWSQ5V2lFRePanG0N0oOpZGiO3yfq38F1RX
         5W6hDm5ZdT/rlOJ090PGOOwBbbu7XDdGsVwL18pSDXHh+KjbD7G8Vp1jt1kXXynL862X
         f4n4K0hQFlSYCnscz3S2rkLL8muYBE8zqFRjiKHlf4h1RPWQd5hjgWgAy7fJPrOXO56b
         4LtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ex8G2A6+;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id h6si445598vkc.3.2020.03.05.07.00.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Mar 2020 07:00:57 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id p62so5564808qkb.0
        for <kasan-dev@googlegroups.com>; Thu, 05 Mar 2020 07:00:57 -0800 (PST)
X-Received: by 2002:ae9:e003:: with SMTP id m3mr8719872qkk.250.1583420455002;
 Thu, 05 Mar 2020 07:00:55 -0800 (PST)
MIME-Version: 1.0
References: <202002292221.D4YLxcV6%lkp@intel.com> <20200305134341.GY2596@hirez.programming.kicks-ass.net>
In-Reply-To: <20200305134341.GY2596@hirez.programming.kicks-ass.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Mar 2020 16:00:42 +0100
Message-ID: <CACT4Y+apHDVM7u8f660vc3orkHtCXY+ZGgn_Ueu_eXDxDw3Dgw@mail.gmail.com>
Subject: Re: [peterz-queue:core/rcu 31/33] arch/x86/kernel/alternative.c:961:26:
 error: inlining failed in call to always_inline 'try_get_desc': function
 attribute mismatch
To: Peter Zijlstra <peterz@infradead.org>
Cc: kbuild test robot <lkp@intel.com>, kbuild-all@lists.01.org, 
	Thomas Gleixner <tglx@linutronix.de>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ex8G2A6+;       spf=pass
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

On Thu, Mar 5, 2020 at 2:43 PM Peter Zijlstra <peterz@infradead.org> wrote:
>
>
> Dmitry; I keep getting this from the 0day robot, but I can't reproduce
> locally (with GCC-8 and up).
>
> The alternative to having that __no_sanitize is moving the code that
> wants this into it's own .c file and using the Makefile hacks to kills
> everything dead, but that's cumbersome too.
>
> The thing is, Thomas is reworking the x86 entry code and we're moving a
> whole bunch of that into C, those early entry functions also all want
> this.
>
> Do you have any clues as to what gcc-7 is on about and what, if
> anything, we can do about this?

Hi Peter,

I can reproduce this on:

commit 38b47f3cd6f56a0616b0503bbd58c9ab8b3511e9 (HEAD)
   x86/int3: Ensure that poke_int3_handler() is not sanitized

with a small diff:

--- a/include/linux/rcupdate.h
+++ b/include/linux/rcupdate.h
@@ -194,14 +194,14 @@ static inline int trace_rcu_enter(void)
 {
        int state = !rcu_is_watching();
        if (state)
-               rcu_irq_enter_irqsave();
+               rcu_irq_enter_irqsafe();
        return state;
 }

 static inline void trace_rcu_exit(int state)
 {
        if (state)
-               rcu_irq_exit_irqsave();
+               rcu_irq_exit_irqsafe();
 }

by running:

make CC=gcc-7 arch/x86/kernel/alternative.o
make CC=gcc-8 arch/x86/kernel/alternative.o


Question: do we need/want to not kasan-instrument user_mode?





> On Sat, Feb 29, 2020 at 10:37:26PM +0800, kbuild test robot wrote:
> > tree:   https://git.kernel.org/pub/scm/linux/kernel/git/peterz/queue.git core/rcu
> > head:   bc72cd8dac4be9572f0cae33b096f9c23460e08a
> > commit: 2834aaec9e68691ed8d74bdfd3bbea47b6b3972f [31/33] x86/int3: Ensure that poke_int3_handler() is not sanitized
> > config: x86_64-allmodconfig (attached as .config)
> > compiler: gcc-7 (Debian 7.5.0-5) 7.5.0
> > reproduce:
> >         git checkout 2834aaec9e68691ed8d74bdfd3bbea47b6b3972f
> >         # save the attached .config to linux build tree
> >         make ARCH=x86_64
> >
> > If you fix the issue, kindly add following tag
> > Reported-by: kbuild test robot <lkp@intel.com>
> >
> > All errors (new ones prefixed by >>):
> >
> >    In file included from arch/x86/include/asm/math_emu.h:5:0,
> >                     from arch/x86/include/asm/processor.h:13,
> >                     from arch/x86/include/asm/cpufeature.h:5,
> >                     from arch/x86/include/asm/thread_info.h:53,
> >                     from include/linux/thread_info.h:38,
> >                     from arch/x86/include/asm/preempt.h:7,
> >                     from include/linux/preempt.h:78,
> >                     from include/linux/spinlock.h:51,
> >                     from include/linux/seqlock.h:36,
> >                     from include/linux/time.h:6,
> >                     from include/linux/stat.h:19,
> >                     from include/linux/module.h:13,
> >                     from arch/x86/kernel/alternative.c:4:
> >    arch/x86/kernel/alternative.c: In function 'poke_int3_handler':
> >    arch/x86/include/asm/ptrace.h:126:28: error: inlining failed in call to always_inline 'user_mode': function attribute mismatch
> >     static __always_inline int user_mode(struct pt_regs *regs)
> >                                ^~~~~~~~~
> >    arch/x86/kernel/alternative.c:1000:6: note: called from here
> >      if (user_mode(regs))
> >          ^~~~~~~~~~~~~~~
> > >> arch/x86/kernel/alternative.c:961:26: error: inlining failed in call to always_inline 'try_get_desc': function attribute mismatch
> >     struct bp_patching_desc *try_get_desc(struct bp_patching_desc **descp)
> >                              ^~~~~~~~~~~~
> >    arch/x86/kernel/alternative.c:1013:7: note: called from here
> >      desc = try_get_desc(&bp_desc);
> >      ~~~~~^~~~~~~~~~~~~~~~~~~~~~~~
> >    In file included from arch/x86/kernel/alternative.c:17:0:
> > >> include/linux/bsearch.h:8:7: error: inlining failed in call to always_inline '__bsearch': function attribute mismatch
> >     void *__bsearch(const void *key, const void *base, size_t num, size_t size, cmp_func_t cmp)
> >           ^~~~~~~~~
> >    arch/x86/kernel/alternative.c:1026:6: note: called from here
> >       tp = __bsearch(ip, desc->vec, desc->nr_entries,
> >       ~~~^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> >               sizeof(struct text_poke_loc),
> >               ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> >               patch_cmp);
> >               ~~~~~~~~~~
> >    arch/x86/kernel/alternative.c:977:30: error: inlining failed in call to always_inline 'text_poke_addr': function attribute mismatch
> >     static __always_inline void *text_poke_addr(struct text_poke_loc *tp)
> >                                  ^~~~~~~~~~~~~~
> >    arch/x86/kernel/alternative.c:1033:7: note: called from here
> >       if (text_poke_addr(tp) != ip)
> >           ^~~~~~~~~~~~~~~~~~
> >    In file included from arch/x86/include/asm/kprobes.h:18:0,
> >                     from include/linux/kprobes.h:30,
> >                     from arch/x86/kernel/alternative.c:15:
> > >> arch/x86/include/asm/text-patching.h:67:28: error: inlining failed in call to always_inline 'text_opcode_size': function attribute mismatch
> >     static __always_inline int text_opcode_size(u8 opcode)
> >                                ^~~~~~~~~~~~~~~~
> >    arch/x86/kernel/alternative.c:1037:6: note: called from here
> >      len = text_opcode_size(tp->opcode);
> >      ~~~~^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> >    In file included from arch/x86/include/asm/kprobes.h:18:0,
> >                     from include/linux/kprobes.h:30,
> >                     from arch/x86/kernel/alternative.c:15:
> > >> arch/x86/include/asm/text-patching.h:144:6: error: inlining failed in call to always_inline 'int3_emulate_call': function attribute mismatch
> >     void int3_emulate_call(struct pt_regs *regs, unsigned long func)
> >          ^~~~~~~~~~~~~~~~~
> >    arch/x86/kernel/alternative.c:1049:3: note: called from here
> >       int3_emulate_call(regs, (long)ip + tp->rel32);
> >       ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> >    In file included from arch/x86/include/asm/kprobes.h:18:0,
> >                     from include/linux/kprobes.h:30,
> >                     from arch/x86/kernel/alternative.c:15:
> > >> arch/x86/include/asm/text-patching.h:122:6: error: inlining failed in call to always_inline 'int3_emulate_jmp': function attribute mismatch
> >     void int3_emulate_jmp(struct pt_regs *regs, unsigned long ip)
> >          ^~~~~~~~~~~~~~~~
> >    arch/x86/kernel/alternative.c:1054:3: note: called from here
> >       int3_emulate_jmp(regs, (long)ip + tp->rel32);
> >       ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > >> arch/x86/kernel/alternative.c:971:29: error: inlining failed in call to always_inline 'put_desc': function attribute mismatch
> >     static __always_inline void put_desc(struct bp_patching_desc *desc)
> >                                 ^~~~~~~~
> >    arch/x86/kernel/alternative.c:1064:2: note: called from here
> >      put_desc(desc);
> >      ^~~~~~~~~~~~~~
> > --
> >    In file included from include/linux/preempt.h:78:0,
> >                     from include/linux/rcupdate.h:27,
> >                     from include/linux/rculist.h:11,
> >                     from include/linux/pid.h:5,
> >                     from include/linux/sched.h:14,
> >                     from include/linux/context_tracking.h:5,
> >                     from arch/x86/kernel/traps.c:15:
> >    arch/x86/kernel/traps.c: In function 'do_int3':
> > >> arch/x86/include/asm/preempt.h:24:28: error: inlining failed in call to always_inline 'preempt_count': function attribute mismatch
> >     static __always_inline int preempt_count(void)
> >                                ^~~~~~~~~~~~~
> >    In file included from arch/x86/include/asm/current.h:5:0,
> >                     from include/linux/sched.h:12,
> >                     from include/linux/context_tracking.h:5,
> >                     from arch/x86/kernel/traps.c:15:
> >    include/linux/preempt.h:102:20: note: called from here
> >     #define in_nmi()  (preempt_count() & NMI_MASK)
> >                        ^~~~~~~~~~~~~~~
> >    include/linux/compiler.h:78:42: note: in definition of macro 'unlikely'
> >     # define unlikely(x) __builtin_expect(!!(x), 0)
> >                                              ^
> >    include/linux/hardirq.h:86:3: note: in expansion of macro 'BUG_ON'
> >       BUG_ON(in_nmi() == NMI_MASK);   \
> >       ^~~~~~
> >    include/linux/hardirq.h:86:10: note: in expansion of macro 'in_nmi'
> >       BUG_ON(in_nmi() == NMI_MASK);   \
> >              ^~~~~~
> >    arch/x86/kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> >      nmi_enter();
> >      ^~~~~~~~~
> >    In file included from include/linux/hardirq.h:7:0,
> >                     from include/linux/interrupt.h:11,
> >                     from arch/x86/kernel/traps.c:16:
> > >> include/linux/ftrace_irq.h:10:29: error: inlining failed in call to always_inline 'ftrace_nmi_enter': function attribute mismatch
> >     static __always_inline void ftrace_nmi_enter(void)
> >                                 ^~~~~~~~~~~~~~~~
> >    In file included from include/linux/interrupt.h:11:0,
> >                     from arch/x86/kernel/traps.c:16:
> >    include/linux/hardirq.h:85:3: note: called from here
> >       ftrace_nmi_enter();    \
> >       ^~~~~~~~~~~~~~~~~~
> >    arch/x86/kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> >      nmi_enter();
> >      ^~~~~~~~~
> >    In file included from include/linux/sched.h:12:0,
> >                     from include/linux/context_tracking.h:5,
> >                     from arch/x86/kernel/traps.c:15:
> > >> arch/x86/include/asm/current.h:13:44: error: inlining failed in call to always_inline 'get_current': function attribute mismatch
> >     static __always_inline struct task_struct *get_current(void)
> >                                                ^~~~~~~~~~~
> >    arch/x86/include/asm/current.h:18:17: note: called from here
> >     #define current get_current()
> >                     ^~~~~~~~~~~~~
> >    include/linux/lockdep.h:304:2: note: in expansion of macro 'current'
> >      current->lockdep_recursion += LOCKDEP_OFF; \
> >      ^~~~~~~
> >    include/linux/hardirq.h:84:3: note: in expansion of macro 'lockdep_off'
> >       lockdep_off();     \
> >       ^~~~~~~~~~~
> >    arch/x86/kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> >      nmi_enter();
> >      ^~~~~~~~~
> > >> arch/x86/include/asm/current.h:13:44: error: inlining failed in call to always_inline 'get_current': function attribute mismatch
> >     static __always_inline struct task_struct *get_current(void)
> >                                                ^~~~~~~~~~~
> >    arch/x86/include/asm/current.h:18:17: note: called from here
> >     #define current get_current()
> >                     ^~~~~~~~~~~~~
> >    include/linux/irqflags.h:40:2: note: in expansion of macro 'current'
> >      current->hardirq_context++;  \
> >      ^~~~~~~
> >    include/linux/hardirq.h:89:3: note: in expansion of macro 'trace_hardirq_enter'
> >       trace_hardirq_enter();    \
> >       ^~~~~~~~~~~~~~~~~~~
> >    arch/x86/kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> >      nmi_enter();
> >      ^~~~~~~~~
> >    In file included from include/linux/preempt.h:78:0,
> >                     from include/linux/rcupdate.h:27,
> >                     from include/linux/rculist.h:11,
> >                     from include/linux/pid.h:5,
> >                     from include/linux/sched.h:14,
> >                     from include/linux/context_tracking.h:5,
> >                     from arch/x86/kernel/traps.c:15:
> >    arch/x86/include/asm/preempt.h:77:29: error: inlining failed in call to always_inline '__preempt_count_add': function attribute mismatch
> >     static __always_inline void __preempt_count_add(int val)
> >                                 ^~~~~~~~~~~~~~~~~~~
> >    In file included from include/linux/interrupt.h:11:0,
> >                     from arch/x86/kernel/traps.c:16:
> >    include/linux/hardirq.h:87:3: note: called from here
> >       __preempt_count_add(NMI_OFFSET + HARDIRQ_OFFSET); \
> >       ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> >    arch/x86/kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> >      nmi_enter();
> >      ^~~~~~~~~
> >    In file included from include/linux/preempt.h:78:0,
> >                     from include/linux/rcupdate.h:27,
> >                     from include/linux/rculist.h:11,
> >                     from include/linux/pid.h:5,
> >                     from include/linux/sched.h:14,
> >                     from include/linux/context_tracking.h:5,
> >                     from arch/x86/kernel/traps.c:15:
> > >> arch/x86/include/asm/preempt.h:24:28: error: inlining failed in call to always_inline 'preempt_count': function attribute mismatch
> >     static __always_inline int preempt_count(void)
> >                                ^~~~~~~~~~~~~
> >    In file included from arch/x86/include/asm/current.h:5:0,
> >                     from include/linux/sched.h:12,
> >                     from include/linux/context_tracking.h:5,
> >                     from arch/x86/kernel/traps.c:15:
> >    include/linux/preempt.h:102:20: note: called from here
> >     #define in_nmi()  (preempt_count() & NMI_MASK)
> >                        ^~~~~~~~~~~~~~~
> >    include/linux/compiler.h:78:42: note: in definition of macro 'unlikely'
> >     # define unlikely(x) __builtin_expect(!!(x), 0)
> >                                              ^
> >    include/linux/hardirq.h:96:3: note: in expansion of macro 'BUG_ON'
> >       BUG_ON(!in_nmi());    \
> >       ^~~~~~
> >    include/linux/hardirq.h:96:11: note: in expansion of macro 'in_nmi'
> >       BUG_ON(!in_nmi());    \
> >               ^~~~~~
> >    arch/x86/kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> >      nmi_exit();
> >      ^~~~~~~~
> >    In file included from include/linux/sched.h:12:0,
> >                     from include/linux/context_tracking.h:5,
> >                     from arch/x86/kernel/traps.c:15:
> > >> arch/x86/include/asm/current.h:13:44: error: inlining failed in call to always_inline 'get_current': function attribute mismatch
> >     static __always_inline struct task_struct *get_current(void)
> >                                                ^~~~~~~~~~~
> >    arch/x86/include/asm/current.h:18:17: note: called from here
> >     #define current get_current()
> >                     ^~~~~~~~~~~~~
> >    include/linux/irqflags.h:44:2: note: in expansion of macro 'current'
> >      current->hardirq_context--;  \
> >      ^~~~~~~
> >    include/linux/hardirq.h:94:3: note: in expansion of macro 'trace_hardirq_exit'
> >       trace_hardirq_exit();    \
> >       ^~~~~~~~~~~~~~~~~~
> >    arch/x86/kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> >      nmi_exit();
> >      ^~~~~~~~
> > >> arch/x86/include/asm/current.h:13:44: error: inlining failed in call to always_inline 'get_current': function attribute mismatch
> >     static __always_inline struct task_struct *get_current(void)
> >                                                ^~~~~~~~~~~
> >    arch/x86/include/asm/current.h:18:17: note: called from here
> >     #define current get_current()
> >                     ^~~~~~~~~~~~~
> >    include/linux/lockdep.h:309:2: note: in expansion of macro 'current'
> >      current->lockdep_recursion -= LOCKDEP_OFF; \
> >      ^~~~~~~
> >    include/linux/hardirq.h:99:3: note: in expansion of macro 'lockdep_on'
> >       lockdep_on();     \
> >       ^~~~~~~~~~
> >    arch/x86/kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> >      nmi_exit();
> >      ^~~~~~~~
> >    In file included from include/linux/hardirq.h:7:0,
> >                     from include/linux/interrupt.h:11,
> >                     from arch/x86/kernel/traps.c:16:
> > >> include/linux/ftrace_irq.h:18:29: error: inlining failed in call to always_inline 'ftrace_nmi_exit': function attribute mismatch
> >     static __always_inline void ftrace_nmi_exit(void)
> >                                 ^~~~~~~~~~~~~~~
> >    In file included from include/linux/interrupt.h:11:0,
> >                     from arch/x86/kernel/traps.c:16:
> >    include/linux/hardirq.h:98:3: note: called from here
> >       ftrace_nmi_exit();    \
> >       ^~~~~~~~~~~~~~~~~
> >    arch/x86/kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> >      nmi_exit();
> >      ^~~~~~~~
> >    In file included from include/linux/preempt.h:78:0,
> >                     from include/linux/rcupdate.h:27,
> >                     from include/linux/rculist.h:11,
> >                     from include/linux/pid.h:5,
> >                     from include/linux/sched.h:14,
> >                     from include/linux/context_tracking.h:5,
> >                     from arch/x86/kernel/traps.c:15:
> >    arch/x86/include/asm/preempt.h:82:29: error: inlining failed in call to always_inline '__preempt_count_sub': function attribute mismatch
> >     static __always_inline void __preempt_count_sub(int val)
> >                                 ^~~~~~~~~~~~~~~~~~~
> >    In file included from include/linux/interrupt.h:11:0,
> >                     from arch/x86/kernel/traps.c:16:
> >    include/linux/hardirq.h:97:3: note: called from here
> >       __preempt_count_sub(NMI_OFFSET + HARDIRQ_OFFSET); \
> >       ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> >    arch/x86/kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> >      nmi_exit();
> >      ^~~~~~~~
> > --
> >    In file included from include/linux/preempt.h:78:0,
> >                     from include/linux/rcupdate.h:27,
> >                     from include/linux/rculist.h:11,
> >                     from include/linux/pid.h:5,
> >                     from include/linux/sched.h:14,
> >                     from include/linux/context_tracking.h:5,
> >                     from arch/x86//kernel/traps.c:15:
> >    arch/x86//kernel/traps.c: In function 'do_int3':
> > >> arch/x86/include/asm/preempt.h:24:28: error: inlining failed in call to always_inline 'preempt_count': function attribute mismatch
> >     static __always_inline int preempt_count(void)
> >                                ^~~~~~~~~~~~~
> >    In file included from arch/x86/include/asm/current.h:5:0,
> >                     from include/linux/sched.h:12,
> >                     from include/linux/context_tracking.h:5,
> >                     from arch/x86//kernel/traps.c:15:
> >    include/linux/preempt.h:102:20: note: called from here
> >     #define in_nmi()  (preempt_count() & NMI_MASK)
> >                        ^~~~~~~~~~~~~~~
> >    include/linux/compiler.h:78:42: note: in definition of macro 'unlikely'
> >     # define unlikely(x) __builtin_expect(!!(x), 0)
> >                                              ^
> >    include/linux/hardirq.h:86:3: note: in expansion of macro 'BUG_ON'
> >       BUG_ON(in_nmi() == NMI_MASK);   \
> >       ^~~~~~
> >    include/linux/hardirq.h:86:10: note: in expansion of macro 'in_nmi'
> >       BUG_ON(in_nmi() == NMI_MASK);   \
> >              ^~~~~~
> >    arch/x86//kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> >      nmi_enter();
> >      ^~~~~~~~~
> >    In file included from include/linux/hardirq.h:7:0,
> >                     from include/linux/interrupt.h:11,
> >                     from arch/x86//kernel/traps.c:16:
> > >> include/linux/ftrace_irq.h:10:29: error: inlining failed in call to always_inline 'ftrace_nmi_enter': function attribute mismatch
> >     static __always_inline void ftrace_nmi_enter(void)
> >                                 ^~~~~~~~~~~~~~~~
> >    In file included from include/linux/interrupt.h:11:0,
> >                     from arch/x86//kernel/traps.c:16:
> >    include/linux/hardirq.h:85:3: note: called from here
> >       ftrace_nmi_enter();    \
> >       ^~~~~~~~~~~~~~~~~~
> >    arch/x86//kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> >      nmi_enter();
> >      ^~~~~~~~~
> >    In file included from include/linux/sched.h:12:0,
> >                     from include/linux/context_tracking.h:5,
> >                     from arch/x86//kernel/traps.c:15:
> > >> arch/x86/include/asm/current.h:13:44: error: inlining failed in call to always_inline 'get_current': function attribute mismatch
> >     static __always_inline struct task_struct *get_current(void)
> >                                                ^~~~~~~~~~~
> >    arch/x86/include/asm/current.h:18:17: note: called from here
> >     #define current get_current()
> >                     ^~~~~~~~~~~~~
> >    include/linux/lockdep.h:304:2: note: in expansion of macro 'current'
> >      current->lockdep_recursion += LOCKDEP_OFF; \
> >      ^~~~~~~
> >    include/linux/hardirq.h:84:3: note: in expansion of macro 'lockdep_off'
> >       lockdep_off();     \
> >       ^~~~~~~~~~~
> >    arch/x86//kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> >      nmi_enter();
> >      ^~~~~~~~~
> > >> arch/x86/include/asm/current.h:13:44: error: inlining failed in call to always_inline 'get_current': function attribute mismatch
> >     static __always_inline struct task_struct *get_current(void)
> >                                                ^~~~~~~~~~~
> >    arch/x86/include/asm/current.h:18:17: note: called from here
> >     #define current get_current()
> >                     ^~~~~~~~~~~~~
> >    include/linux/irqflags.h:40:2: note: in expansion of macro 'current'
> >      current->hardirq_context++;  \
> >      ^~~~~~~
> >    include/linux/hardirq.h:89:3: note: in expansion of macro 'trace_hardirq_enter'
> >       trace_hardirq_enter();    \
> >       ^~~~~~~~~~~~~~~~~~~
> >    arch/x86//kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> >      nmi_enter();
> >      ^~~~~~~~~
> >    In file included from include/linux/preempt.h:78:0,
> >                     from include/linux/rcupdate.h:27,
> >                     from include/linux/rculist.h:11,
> >                     from include/linux/pid.h:5,
> >                     from include/linux/sched.h:14,
> >                     from include/linux/context_tracking.h:5,
> >                     from arch/x86//kernel/traps.c:15:
> >    arch/x86/include/asm/preempt.h:77:29: error: inlining failed in call to always_inline '__preempt_count_add': function attribute mismatch
> >     static __always_inline void __preempt_count_add(int val)
> >                                 ^~~~~~~~~~~~~~~~~~~
> >    In file included from include/linux/interrupt.h:11:0,
> >                     from arch/x86//kernel/traps.c:16:
> >    include/linux/hardirq.h:87:3: note: called from here
> >       __preempt_count_add(NMI_OFFSET + HARDIRQ_OFFSET); \
> >       ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> >    arch/x86//kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> >      nmi_enter();
> >      ^~~~~~~~~
> >    In file included from include/linux/preempt.h:78:0,
> >                     from include/linux/rcupdate.h:27,
> >                     from include/linux/rculist.h:11,
> >                     from include/linux/pid.h:5,
> >                     from include/linux/sched.h:14,
> >                     from include/linux/context_tracking.h:5,
> >                     from arch/x86//kernel/traps.c:15:
> > >> arch/x86/include/asm/preempt.h:24:28: error: inlining failed in call to always_inline 'preempt_count': function attribute mismatch
> >     static __always_inline int preempt_count(void)
> >                                ^~~~~~~~~~~~~
> >    In file included from arch/x86/include/asm/current.h:5:0,
> >                     from include/linux/sched.h:12,
> >                     from include/linux/context_tracking.h:5,
> >                     from arch/x86//kernel/traps.c:15:
> >    include/linux/preempt.h:102:20: note: called from here
> >     #define in_nmi()  (preempt_count() & NMI_MASK)
> >                        ^~~~~~~~~~~~~~~
> >    include/linux/compiler.h:78:42: note: in definition of macro 'unlikely'
> >     # define unlikely(x) __builtin_expect(!!(x), 0)
> >                                              ^
> >    include/linux/hardirq.h:96:3: note: in expansion of macro 'BUG_ON'
> >       BUG_ON(!in_nmi());    \
> >       ^~~~~~
> >    include/linux/hardirq.h:96:11: note: in expansion of macro 'in_nmi'
> >       BUG_ON(!in_nmi());    \
> >               ^~~~~~
> >    arch/x86//kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> >      nmi_exit();
> >      ^~~~~~~~
> >    In file included from include/linux/sched.h:12:0,
> >                     from include/linux/context_tracking.h:5,
> >                     from arch/x86//kernel/traps.c:15:
> > >> arch/x86/include/asm/current.h:13:44: error: inlining failed in call to always_inline 'get_current': function attribute mismatch
> >     static __always_inline struct task_struct *get_current(void)
> >                                                ^~~~~~~~~~~
> >    arch/x86/include/asm/current.h:18:17: note: called from here
> >     #define current get_current()
> >                     ^~~~~~~~~~~~~
> >    include/linux/irqflags.h:44:2: note: in expansion of macro 'current'
> >      current->hardirq_context--;  \
> >      ^~~~~~~
> >    include/linux/hardirq.h:94:3: note: in expansion of macro 'trace_hardirq_exit'
> >       trace_hardirq_exit();    \
> >       ^~~~~~~~~~~~~~~~~~
> >    arch/x86//kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> >      nmi_exit();
> >      ^~~~~~~~
> > >> arch/x86/include/asm/current.h:13:44: error: inlining failed in call to always_inline 'get_current': function attribute mismatch
> >     static __always_inline struct task_struct *get_current(void)
> >                                                ^~~~~~~~~~~
> >    arch/x86/include/asm/current.h:18:17: note: called from here
> >     #define current get_current()
> >                     ^~~~~~~~~~~~~
> >    include/linux/lockdep.h:309:2: note: in expansion of macro 'current'
> >      current->lockdep_recursion -= LOCKDEP_OFF; \
> >      ^~~~~~~
> >    include/linux/hardirq.h:99:3: note: in expansion of macro 'lockdep_on'
> >       lockdep_on();     \
> >       ^~~~~~~~~~
> >    arch/x86//kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> >      nmi_exit();
> >      ^~~~~~~~
> >    In file included from include/linux/hardirq.h:7:0,
> >                     from include/linux/interrupt.h:11,
> >                     from arch/x86//kernel/traps.c:16:
> > >> include/linux/ftrace_irq.h:18:29: error: inlining failed in call to always_inline 'ftrace_nmi_exit': function attribute mismatch
> >     static __always_inline void ftrace_nmi_exit(void)
> >                                 ^~~~~~~~~~~~~~~
> >    In file included from include/linux/interrupt.h:11:0,
> >                     from arch/x86//kernel/traps.c:16:
> >    include/linux/hardirq.h:98:3: note: called from here
> >       ftrace_nmi_exit();    \
> >       ^~~~~~~~~~~~~~~~~
> >    arch/x86//kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> >      nmi_exit();
> >      ^~~~~~~~
> >    In file included from include/linux/preempt.h:78:0,
> >                     from include/linux/rcupdate.h:27,
> >                     from include/linux/rculist.h:11,
> >                     from include/linux/pid.h:5,
> >                     from include/linux/sched.h:14,
> >                     from include/linux/context_tracking.h:5,
> >                     from arch/x86//kernel/traps.c:15:
> >    arch/x86/include/asm/preempt.h:82:29: error: inlining failed in call to always_inline '__preempt_count_sub': function attribute mismatch
> >     static __always_inline void __preempt_count_sub(int val)
> >                                 ^~~~~~~~~~~~~~~~~~~
> >    In file included from include/linux/interrupt.h:11:0,
> >                     from arch/x86//kernel/traps.c:16:
> >    include/linux/hardirq.h:97:3: note: called from here
> >       __preempt_count_sub(NMI_OFFSET + HARDIRQ_OFFSET); \
> >       ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> >    arch/x86//kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> >      nmi_exit();
> >      ^~~~~~~~
> > ..
> >
> > vim +/try_get_desc +961 arch/x86/kernel/alternative.c
> >
> > 1f676247f36a4b Peter Zijlstra             2019-12-11  959
> > 809106a6157bce Thomas Gleixner            2020-01-21  960  static __always_inline
> > 809106a6157bce Thomas Gleixner            2020-01-21 @961  struct bp_patching_desc *try_get_desc(struct bp_patching_desc **descp)
> > 1f676247f36a4b Peter Zijlstra             2019-12-11  962  {
> > a9d380bd4091e7 Peter Zijlstra             2020-01-24  963     struct bp_patching_desc *desc = READ_ONCE_NOCHECK(*descp); /* rcu_dereference */
> > 1f676247f36a4b Peter Zijlstra             2019-12-11  964
> > a9d380bd4091e7 Peter Zijlstra             2020-01-24  965     if (!desc || !arch_atomic_inc_not_zero(&desc->refs))
> > 1f676247f36a4b Peter Zijlstra             2019-12-11  966             return NULL;
> > 1f676247f36a4b Peter Zijlstra             2019-12-11  967
> > 1f676247f36a4b Peter Zijlstra             2019-12-11  968     return desc;
> > 1f676247f36a4b Peter Zijlstra             2019-12-11  969  }
> > 1f676247f36a4b Peter Zijlstra             2019-12-11  970
> > 809106a6157bce Thomas Gleixner            2020-01-21 @971  static __always_inline void put_desc(struct bp_patching_desc *desc)
> > 1f676247f36a4b Peter Zijlstra             2019-12-11  972  {
> > 1f676247f36a4b Peter Zijlstra             2019-12-11  973     smp_mb__before_atomic();
> > a9d380bd4091e7 Peter Zijlstra             2020-01-24  974     arch_atomic_dec(&desc->refs);
> > 1f676247f36a4b Peter Zijlstra             2019-12-11  975  }
> > c0213b0ac03cf6 Daniel Bristot de Oliveira 2019-06-12  976
> >
> > :::::: The code at line 961 was first introduced by commit
> > :::::: 809106a6157bce0fff76bfc7864e7ce34080abe0 x86/int3: Ensure that poke_int3_handler() is not traced
> >
> > :::::: TO: Thomas Gleixner <tglx@linutronix.de>
> > :::::: CC: Peter Zijlstra <peterz@infradead.org>
> >
> > ---
> > 0-DAY CI Kernel Test Service, Intel Corporation
> > https://lists.01.org/hyperkitty/list/kbuild-all@lists.01.org
>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BapHDVM7u8f660vc3orkHtCXY%2BZGgn_Ueu_eXDxDw3Dgw%40mail.gmail.com.
