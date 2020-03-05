Return-Path: <kasan-dev+bncBCMIZB7QWENRB3FSQTZQKGQE5KVEUFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3c.google.com (mail-yw1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2290517A8C6
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Mar 2020 16:23:26 +0100 (CET)
Received: by mail-yw1-xc3c.google.com with SMTP id w185sf8015995ywa.22
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2020 07:23:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583421805; cv=pass;
        d=google.com; s=arc-20160816;
        b=yNPMVC6zpGgw7v4iDOppbtgRer3mFZlWP7o09KZIu/mEmkkK32eW4Hjhil8kQuuN+F
         kT0P0iSsWHsiDfd+GmlR15EPQNgnmHEy302ACkY57xqkWhxB1/jOQVyI5otNhi+V1QPV
         s8cUAnRWkfXkG2fNowhaIrRUDR59x8kVtymCvvyOcj9ICfx494FJFiotNLbqp/aiqkfB
         w0wBz5Wz9yA48bcVUHedJDCp0T2/sdgCUZU9+j/bIcySZXb4W0LfsuPm7XEyj90dgWnH
         gVXWlCW/aelEcnwjUHt2XsfXpt3bJRBKBTlLjsX2hQRxgQBU4/cDMNKUIV5vzyK3mrMi
         SNoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ZTIvxuSpAkiyjkeam2rLeS2Rui+TCZDyLoG8jiR/oqg=;
        b=TVHx3eO0v8gmeAoSd+0HIOcWDG6wE1K/BrCi8WLW632OBfU5K8OLCAd4a7RCGfrowd
         ge3VmAvVGNe9dgOkQGVAjhJP+PhhkhQwLWptHnLWfnGlcH3QU8qSjzJ5JIu2IBWhgHc3
         R//6CZc5bL3d7au+WXUOBs2y2wsEV+C9WLtS1VIxTZ8uik1/wsGl7v9ojS/Uegglbz1R
         XmV4xutigD5NGI97anK1E/t2pShu+pDyFTZSkG5Ksu08bU+jO5l+gPWxCj7x2Q+MByLc
         a5C5X/ak2CMYv/V1Co4H6wSVKnOKoK3ILp2sMmqYT1fWa9DHteVerKlBE/Hyali6T1++
         GWrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AEd2gfUd;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZTIvxuSpAkiyjkeam2rLeS2Rui+TCZDyLoG8jiR/oqg=;
        b=RlJ+JTHZFS0n/WGoTuArI+tgxGFN3yoaUX7krKZKz9yo2/4KQWMsabbQP2MWKzv9zo
         jLdm8/MqaEKEpjq0s4TRaFkDMCEuPSwTC2MfQRbidCGcDkegUro5Ays7gvsmT0J8j95/
         Zeo8bsSCzPFuVLuje8Qz3G9pTxkc010EcnN7GpgESuXSXDN7IiRifwqaTXvgPPFSrJaH
         1VnKfHVoD06cjcho+Xk6SDgdfqADjtKVAuKKYQ3ifh6laYvT2Os/zChFKXif3JoOQGsl
         pKul7Mw5TTbCAw0ZWEfjGRHYTUokVBIawT4P4EtmT/wa5q+Rbeee7kYenkzBU7kdRlV2
         9MTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZTIvxuSpAkiyjkeam2rLeS2Rui+TCZDyLoG8jiR/oqg=;
        b=HtkFv48XA/5U1B+ZN5mc4bqCO3q/joHuAwyVftpAIUc2F13dBn+Y5NsrQT+hd6nbEh
         QrfjsucWuXkwHYNwUU1ExPnguEPK0hlWfOeJqSETUz2ELPn08DnueSyX89vettRl+o7t
         bRmXDVfFRKLjdYD6iI+I2DpJPVvlhr5YaNSWykG9t9FYwxmx1pIbm/YaqcLRY0mlIizM
         UQsbxz7XGQQobWzdwwP4GLOit38B4GeAeNNt/Fx1UUCHVwLs9ax+t+V4gy/HeCuOEeeS
         tQMgFg1UkZy328TPsg0cxnCLxP/FW7Hqh1nRp5Iuaqxw4A8yKBaEC6aKoWOMOEMbo+YQ
         zKBQ==
X-Gm-Message-State: ANhLgQ2m6jyLSvuQD7RTkYTKbbjM5p1eONgan/JBpsWKm7jjgd7EcKj0
	mcqtD+5J4SA6VGxAhrlS2iY=
X-Google-Smtp-Source: ADFU+vvnPnSZWQuEpNri86P+Rhdb3eHLYYHZz1MOTyD6ltKVifyqhclKbxeR24G9mlmDjaEwxAhaEQ==
X-Received: by 2002:a81:4a46:: with SMTP id x67mr8627410ywa.351.1583421804955;
        Thu, 05 Mar 2020 07:23:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:d889:: with SMTP id a131ls125174ywe.6.gmail; Thu, 05 Mar
 2020 07:23:24 -0800 (PST)
X-Received: by 2002:a0d:c9c3:: with SMTP id l186mr8378773ywd.352.1583421804427;
        Thu, 05 Mar 2020 07:23:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583421804; cv=none;
        d=google.com; s=arc-20160816;
        b=WO+gNiDe1sg2eUsVwe2U5rASWRv52rkp3KSjwRji0N3BePtdX+eqImNdQ1IPMlminO
         m013X56tuB79l0f7K3fpDrFn9TF0dzLBE/xZM+P2A//DqUVQZevx6uTgyMYNfGS+UwYG
         Oq0YmsckY19N8AVTGGPys0LSO8vV/767wEv/2DcQ3WfTYPdShmayRmlrKuxvrOillNLf
         +sAGyl9OnK/bWfIrXD4flkT2f3X5aDQ/AOambNhE7/bDO5Z9NaIq5NfKeS0AxR5WiXHe
         ivNmSPcDbgCIJ8aSLTe/DO9Cso0CrtBCtq4rrMbyIxhAiX3aprdIOy0CG6MS/g8MlenL
         DnnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FH9XGl5z/1O1RFOS2HX0SMXUEg9xAzHgy8vD2fALzDs=;
        b=fn13p5dgU+0aBZ8NqIOZHIxsEh3OSBGRQS6TD3pUfx4BkFhBRL9PJOxq/TuzfZ0DTD
         EkpDMRdSqwfAsC74qwdy1gG3IK4lLX56XnqIisYSdGkqIcljbgyzNz8+CGZC5dRzvNSj
         MsQpbj+BYnDTDqWJu/tQt9c54ZEitqEhbuoq2Vcsix2SRTLNJbwSLJmd8oGoOu1d3w6k
         Tet74xoVrjtK7/il38gZuzpD8PpYtYvrVRiIhcpYATges2HBwKDNiHj3hy96mzOLcuq6
         eU+q2iXWwGsyUjguUBS2H7LJoI4bZwBn1hB4OLTMCpcP+w+DOvA6GdYa7IGpmxbMO8Qq
         MXlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AEd2gfUd;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id u7si448645ywg.5.2020.03.05.07.23.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Mar 2020 07:23:24 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id b5so5631910qkh.8
        for <kasan-dev@googlegroups.com>; Thu, 05 Mar 2020 07:23:24 -0800 (PST)
X-Received: by 2002:a37:7c47:: with SMTP id x68mr8729947qkc.8.1583421803286;
 Thu, 05 Mar 2020 07:23:23 -0800 (PST)
MIME-Version: 1.0
References: <202002292221.D4YLxcV6%lkp@intel.com> <20200305134341.GY2596@hirez.programming.kicks-ass.net>
 <CACT4Y+apHDVM7u8f660vc3orkHtCXY+ZGgn_Ueu_eXDxDw3Dgw@mail.gmail.com> <CACT4Y+ZuGLqNaB+C+VJREtOrnTZVyHLckdAHRMSHF3JMDTg_TA@mail.gmail.com>
In-Reply-To: <CACT4Y+ZuGLqNaB+C+VJREtOrnTZVyHLckdAHRMSHF3JMDTg_TA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Mar 2020 16:23:11 +0100
Message-ID: <CACT4Y+ayJrm6ZrkQwybGZniP-xwtxjkmMpYVdCoU4mKzDUWydQ@mail.gmail.com>
Subject: Re: [peterz-queue:core/rcu 31/33] arch/x86/kernel/alternative.c:961:26:
 error: inlining failed in call to always_inline 'try_get_desc': function
 attribute mismatch
To: Peter Zijlstra <peterz@infradead.org>
Cc: kbuild test robot <lkp@intel.com>, kbuild-all@lists.01.org, 
	Thomas Gleixner <tglx@linutronix.de>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=AEd2gfUd;       spf=pass
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

On Thu, Mar 5, 2020 at 4:10 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Mar 5, 2020 at 4:00 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Thu, Mar 5, 2020 at 2:43 PM Peter Zijlstra <peterz@infradead.org> wrote:
> > >
> > >
> > > Dmitry; I keep getting this from the 0day robot, but I can't reproduce
> > > locally (with GCC-8 and up).
> > >
> > > The alternative to having that __no_sanitize is moving the code that
> > > wants this into it's own .c file and using the Makefile hacks to kills
> > > everything dead, but that's cumbersome too.
> > >
> > > The thing is, Thomas is reworking the x86 entry code and we're moving a
> > > whole bunch of that into C, those early entry functions also all want
> > > this.
> > >
> > > Do you have any clues as to what gcc-7 is on about and what, if
> > > anything, we can do about this?
>
> What we are asking it to do is impossible to satisfy. For now I am
> puzzled as to why gcc-8 does not produce the same warning. I think it
> should. So far I can't find any recent relevant changes in gcc code.


I've tried with manually built gcc in an attempt to try to understand
what has changed between gcc 7 and 8.
I've tried on 8793c0dee2d1282ef76228acfd3c34569ad2a190, it's not the
latest commit, but it's gcc version 9.0.0 20190115
and it produces the same errors about inlining.
So I think that distro-provided gcc-8/9 are just buggy.

Compilers just don't allow this: asking to inline sanitized function
into a non-sanitized function. But I don't know the ptrace/alternative
code good enough to suggest the right alternative (don't call
user_mode, copy user_mode, or something else).

Maybe we could replace no_sanitize with calls to
kasan_disable_current/kasan_enable_current around the section of code
where you don't want to see kasan reports.


> > Hi Peter,
> >
> > I can reproduce this on:
> >
> > commit 38b47f3cd6f56a0616b0503bbd58c9ab8b3511e9 (HEAD)
> >    x86/int3: Ensure that poke_int3_handler() is not sanitized
> >
> > with a small diff:
> >
> > --- a/include/linux/rcupdate.h
> > +++ b/include/linux/rcupdate.h
> > @@ -194,14 +194,14 @@ static inline int trace_rcu_enter(void)
> >  {
> >         int state = !rcu_is_watching();
> >         if (state)
> > -               rcu_irq_enter_irqsave();
> > +               rcu_irq_enter_irqsafe();
> >         return state;
> >  }
> >
> >  static inline void trace_rcu_exit(int state)
> >  {
> >         if (state)
> > -               rcu_irq_exit_irqsave();
> > +               rcu_irq_exit_irqsafe();
> >  }
> >
> > by running:
> >
> > make CC=gcc-7 arch/x86/kernel/alternative.o
> > make CC=gcc-8 arch/x86/kernel/alternative.o
> >
> >
> > Question: do we need/want to not kasan-instrument user_mode?
> >
> >
> >
> >
> >
> > > On Sat, Feb 29, 2020 at 10:37:26PM +0800, kbuild test robot wrote:
> > > > tree:   https://git.kernel.org/pub/scm/linux/kernel/git/peterz/queue.git core/rcu
> > > > head:   bc72cd8dac4be9572f0cae33b096f9c23460e08a
> > > > commit: 2834aaec9e68691ed8d74bdfd3bbea47b6b3972f [31/33] x86/int3: Ensure that poke_int3_handler() is not sanitized
> > > > config: x86_64-allmodconfig (attached as .config)
> > > > compiler: gcc-7 (Debian 7.5.0-5) 7.5.0
> > > > reproduce:
> > > >         git checkout 2834aaec9e68691ed8d74bdfd3bbea47b6b3972f
> > > >         # save the attached .config to linux build tree
> > > >         make ARCH=x86_64
> > > >
> > > > If you fix the issue, kindly add following tag
> > > > Reported-by: kbuild test robot <lkp@intel.com>
> > > >
> > > > All errors (new ones prefixed by >>):
> > > >
> > > >    In file included from arch/x86/include/asm/math_emu.h:5:0,
> > > >                     from arch/x86/include/asm/processor.h:13,
> > > >                     from arch/x86/include/asm/cpufeature.h:5,
> > > >                     from arch/x86/include/asm/thread_info.h:53,
> > > >                     from include/linux/thread_info.h:38,
> > > >                     from arch/x86/include/asm/preempt.h:7,
> > > >                     from include/linux/preempt.h:78,
> > > >                     from include/linux/spinlock.h:51,
> > > >                     from include/linux/seqlock.h:36,
> > > >                     from include/linux/time.h:6,
> > > >                     from include/linux/stat.h:19,
> > > >                     from include/linux/module.h:13,
> > > >                     from arch/x86/kernel/alternative.c:4:
> > > >    arch/x86/kernel/alternative.c: In function 'poke_int3_handler':
> > > >    arch/x86/include/asm/ptrace.h:126:28: error: inlining failed in call to always_inline 'user_mode': function attribute mismatch
> > > >     static __always_inline int user_mode(struct pt_regs *regs)
> > > >                                ^~~~~~~~~
> > > >    arch/x86/kernel/alternative.c:1000:6: note: called from here
> > > >      if (user_mode(regs))
> > > >          ^~~~~~~~~~~~~~~
> > > > >> arch/x86/kernel/alternative.c:961:26: error: inlining failed in call to always_inline 'try_get_desc': function attribute mismatch
> > > >     struct bp_patching_desc *try_get_desc(struct bp_patching_desc **descp)
> > > >                              ^~~~~~~~~~~~
> > > >    arch/x86/kernel/alternative.c:1013:7: note: called from here
> > > >      desc = try_get_desc(&bp_desc);
> > > >      ~~~~~^~~~~~~~~~~~~~~~~~~~~~~~
> > > >    In file included from arch/x86/kernel/alternative.c:17:0:
> > > > >> include/linux/bsearch.h:8:7: error: inlining failed in call to always_inline '__bsearch': function attribute mismatch
> > > >     void *__bsearch(const void *key, const void *base, size_t num, size_t size, cmp_func_t cmp)
> > > >           ^~~~~~~~~
> > > >    arch/x86/kernel/alternative.c:1026:6: note: called from here
> > > >       tp = __bsearch(ip, desc->vec, desc->nr_entries,
> > > >       ~~~^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > > >               sizeof(struct text_poke_loc),
> > > >               ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > > >               patch_cmp);
> > > >               ~~~~~~~~~~
> > > >    arch/x86/kernel/alternative.c:977:30: error: inlining failed in call to always_inline 'text_poke_addr': function attribute mismatch
> > > >     static __always_inline void *text_poke_addr(struct text_poke_loc *tp)
> > > >                                  ^~~~~~~~~~~~~~
> > > >    arch/x86/kernel/alternative.c:1033:7: note: called from here
> > > >       if (text_poke_addr(tp) != ip)
> > > >           ^~~~~~~~~~~~~~~~~~
> > > >    In file included from arch/x86/include/asm/kprobes.h:18:0,
> > > >                     from include/linux/kprobes.h:30,
> > > >                     from arch/x86/kernel/alternative.c:15:
> > > > >> arch/x86/include/asm/text-patching.h:67:28: error: inlining failed in call to always_inline 'text_opcode_size': function attribute mismatch
> > > >     static __always_inline int text_opcode_size(u8 opcode)
> > > >                                ^~~~~~~~~~~~~~~~
> > > >    arch/x86/kernel/alternative.c:1037:6: note: called from here
> > > >      len = text_opcode_size(tp->opcode);
> > > >      ~~~~^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > > >    In file included from arch/x86/include/asm/kprobes.h:18:0,
> > > >                     from include/linux/kprobes.h:30,
> > > >                     from arch/x86/kernel/alternative.c:15:
> > > > >> arch/x86/include/asm/text-patching.h:144:6: error: inlining failed in call to always_inline 'int3_emulate_call': function attribute mismatch
> > > >     void int3_emulate_call(struct pt_regs *regs, unsigned long func)
> > > >          ^~~~~~~~~~~~~~~~~
> > > >    arch/x86/kernel/alternative.c:1049:3: note: called from here
> > > >       int3_emulate_call(regs, (long)ip + tp->rel32);
> > > >       ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > > >    In file included from arch/x86/include/asm/kprobes.h:18:0,
> > > >                     from include/linux/kprobes.h:30,
> > > >                     from arch/x86/kernel/alternative.c:15:
> > > > >> arch/x86/include/asm/text-patching.h:122:6: error: inlining failed in call to always_inline 'int3_emulate_jmp': function attribute mismatch
> > > >     void int3_emulate_jmp(struct pt_regs *regs, unsigned long ip)
> > > >          ^~~~~~~~~~~~~~~~
> > > >    arch/x86/kernel/alternative.c:1054:3: note: called from here
> > > >       int3_emulate_jmp(regs, (long)ip + tp->rel32);
> > > >       ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > > > >> arch/x86/kernel/alternative.c:971:29: error: inlining failed in call to always_inline 'put_desc': function attribute mismatch
> > > >     static __always_inline void put_desc(struct bp_patching_desc *desc)
> > > >                                 ^~~~~~~~
> > > >    arch/x86/kernel/alternative.c:1064:2: note: called from here
> > > >      put_desc(desc);
> > > >      ^~~~~~~~~~~~~~
> > > > --
> > > >    In file included from include/linux/preempt.h:78:0,
> > > >                     from include/linux/rcupdate.h:27,
> > > >                     from include/linux/rculist.h:11,
> > > >                     from include/linux/pid.h:5,
> > > >                     from include/linux/sched.h:14,
> > > >                     from include/linux/context_tracking.h:5,
> > > >                     from arch/x86/kernel/traps.c:15:
> > > >    arch/x86/kernel/traps.c: In function 'do_int3':
> > > > >> arch/x86/include/asm/preempt.h:24:28: error: inlining failed in call to always_inline 'preempt_count': function attribute mismatch
> > > >     static __always_inline int preempt_count(void)
> > > >                                ^~~~~~~~~~~~~
> > > >    In file included from arch/x86/include/asm/current.h:5:0,
> > > >                     from include/linux/sched.h:12,
> > > >                     from include/linux/context_tracking.h:5,
> > > >                     from arch/x86/kernel/traps.c:15:
> > > >    include/linux/preempt.h:102:20: note: called from here
> > > >     #define in_nmi()  (preempt_count() & NMI_MASK)
> > > >                        ^~~~~~~~~~~~~~~
> > > >    include/linux/compiler.h:78:42: note: in definition of macro 'unlikely'
> > > >     # define unlikely(x) __builtin_expect(!!(x), 0)
> > > >                                              ^
> > > >    include/linux/hardirq.h:86:3: note: in expansion of macro 'BUG_ON'
> > > >       BUG_ON(in_nmi() == NMI_MASK);   \
> > > >       ^~~~~~
> > > >    include/linux/hardirq.h:86:10: note: in expansion of macro 'in_nmi'
> > > >       BUG_ON(in_nmi() == NMI_MASK);   \
> > > >              ^~~~~~
> > > >    arch/x86/kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> > > >      nmi_enter();
> > > >      ^~~~~~~~~
> > > >    In file included from include/linux/hardirq.h:7:0,
> > > >                     from include/linux/interrupt.h:11,
> > > >                     from arch/x86/kernel/traps.c:16:
> > > > >> include/linux/ftrace_irq.h:10:29: error: inlining failed in call to always_inline 'ftrace_nmi_enter': function attribute mismatch
> > > >     static __always_inline void ftrace_nmi_enter(void)
> > > >                                 ^~~~~~~~~~~~~~~~
> > > >    In file included from include/linux/interrupt.h:11:0,
> > > >                     from arch/x86/kernel/traps.c:16:
> > > >    include/linux/hardirq.h:85:3: note: called from here
> > > >       ftrace_nmi_enter();    \
> > > >       ^~~~~~~~~~~~~~~~~~
> > > >    arch/x86/kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> > > >      nmi_enter();
> > > >      ^~~~~~~~~
> > > >    In file included from include/linux/sched.h:12:0,
> > > >                     from include/linux/context_tracking.h:5,
> > > >                     from arch/x86/kernel/traps.c:15:
> > > > >> arch/x86/include/asm/current.h:13:44: error: inlining failed in call to always_inline 'get_current': function attribute mismatch
> > > >     static __always_inline struct task_struct *get_current(void)
> > > >                                                ^~~~~~~~~~~
> > > >    arch/x86/include/asm/current.h:18:17: note: called from here
> > > >     #define current get_current()
> > > >                     ^~~~~~~~~~~~~
> > > >    include/linux/lockdep.h:304:2: note: in expansion of macro 'current'
> > > >      current->lockdep_recursion += LOCKDEP_OFF; \
> > > >      ^~~~~~~
> > > >    include/linux/hardirq.h:84:3: note: in expansion of macro 'lockdep_off'
> > > >       lockdep_off();     \
> > > >       ^~~~~~~~~~~
> > > >    arch/x86/kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> > > >      nmi_enter();
> > > >      ^~~~~~~~~
> > > > >> arch/x86/include/asm/current.h:13:44: error: inlining failed in call to always_inline 'get_current': function attribute mismatch
> > > >     static __always_inline struct task_struct *get_current(void)
> > > >                                                ^~~~~~~~~~~
> > > >    arch/x86/include/asm/current.h:18:17: note: called from here
> > > >     #define current get_current()
> > > >                     ^~~~~~~~~~~~~
> > > >    include/linux/irqflags.h:40:2: note: in expansion of macro 'current'
> > > >      current->hardirq_context++;  \
> > > >      ^~~~~~~
> > > >    include/linux/hardirq.h:89:3: note: in expansion of macro 'trace_hardirq_enter'
> > > >       trace_hardirq_enter();    \
> > > >       ^~~~~~~~~~~~~~~~~~~
> > > >    arch/x86/kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> > > >      nmi_enter();
> > > >      ^~~~~~~~~
> > > >    In file included from include/linux/preempt.h:78:0,
> > > >                     from include/linux/rcupdate.h:27,
> > > >                     from include/linux/rculist.h:11,
> > > >                     from include/linux/pid.h:5,
> > > >                     from include/linux/sched.h:14,
> > > >                     from include/linux/context_tracking.h:5,
> > > >                     from arch/x86/kernel/traps.c:15:
> > > >    arch/x86/include/asm/preempt.h:77:29: error: inlining failed in call to always_inline '__preempt_count_add': function attribute mismatch
> > > >     static __always_inline void __preempt_count_add(int val)
> > > >                                 ^~~~~~~~~~~~~~~~~~~
> > > >    In file included from include/linux/interrupt.h:11:0,
> > > >                     from arch/x86/kernel/traps.c:16:
> > > >    include/linux/hardirq.h:87:3: note: called from here
> > > >       __preempt_count_add(NMI_OFFSET + HARDIRQ_OFFSET); \
> > > >       ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > > >    arch/x86/kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> > > >      nmi_enter();
> > > >      ^~~~~~~~~
> > > >    In file included from include/linux/preempt.h:78:0,
> > > >                     from include/linux/rcupdate.h:27,
> > > >                     from include/linux/rculist.h:11,
> > > >                     from include/linux/pid.h:5,
> > > >                     from include/linux/sched.h:14,
> > > >                     from include/linux/context_tracking.h:5,
> > > >                     from arch/x86/kernel/traps.c:15:
> > > > >> arch/x86/include/asm/preempt.h:24:28: error: inlining failed in call to always_inline 'preempt_count': function attribute mismatch
> > > >     static __always_inline int preempt_count(void)
> > > >                                ^~~~~~~~~~~~~
> > > >    In file included from arch/x86/include/asm/current.h:5:0,
> > > >                     from include/linux/sched.h:12,
> > > >                     from include/linux/context_tracking.h:5,
> > > >                     from arch/x86/kernel/traps.c:15:
> > > >    include/linux/preempt.h:102:20: note: called from here
> > > >     #define in_nmi()  (preempt_count() & NMI_MASK)
> > > >                        ^~~~~~~~~~~~~~~
> > > >    include/linux/compiler.h:78:42: note: in definition of macro 'unlikely'
> > > >     # define unlikely(x) __builtin_expect(!!(x), 0)
> > > >                                              ^
> > > >    include/linux/hardirq.h:96:3: note: in expansion of macro 'BUG_ON'
> > > >       BUG_ON(!in_nmi());    \
> > > >       ^~~~~~
> > > >    include/linux/hardirq.h:96:11: note: in expansion of macro 'in_nmi'
> > > >       BUG_ON(!in_nmi());    \
> > > >               ^~~~~~
> > > >    arch/x86/kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> > > >      nmi_exit();
> > > >      ^~~~~~~~
> > > >    In file included from include/linux/sched.h:12:0,
> > > >                     from include/linux/context_tracking.h:5,
> > > >                     from arch/x86/kernel/traps.c:15:
> > > > >> arch/x86/include/asm/current.h:13:44: error: inlining failed in call to always_inline 'get_current': function attribute mismatch
> > > >     static __always_inline struct task_struct *get_current(void)
> > > >                                                ^~~~~~~~~~~
> > > >    arch/x86/include/asm/current.h:18:17: note: called from here
> > > >     #define current get_current()
> > > >                     ^~~~~~~~~~~~~
> > > >    include/linux/irqflags.h:44:2: note: in expansion of macro 'current'
> > > >      current->hardirq_context--;  \
> > > >      ^~~~~~~
> > > >    include/linux/hardirq.h:94:3: note: in expansion of macro 'trace_hardirq_exit'
> > > >       trace_hardirq_exit();    \
> > > >       ^~~~~~~~~~~~~~~~~~
> > > >    arch/x86/kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> > > >      nmi_exit();
> > > >      ^~~~~~~~
> > > > >> arch/x86/include/asm/current.h:13:44: error: inlining failed in call to always_inline 'get_current': function attribute mismatch
> > > >     static __always_inline struct task_struct *get_current(void)
> > > >                                                ^~~~~~~~~~~
> > > >    arch/x86/include/asm/current.h:18:17: note: called from here
> > > >     #define current get_current()
> > > >                     ^~~~~~~~~~~~~
> > > >    include/linux/lockdep.h:309:2: note: in expansion of macro 'current'
> > > >      current->lockdep_recursion -= LOCKDEP_OFF; \
> > > >      ^~~~~~~
> > > >    include/linux/hardirq.h:99:3: note: in expansion of macro 'lockdep_on'
> > > >       lockdep_on();     \
> > > >       ^~~~~~~~~~
> > > >    arch/x86/kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> > > >      nmi_exit();
> > > >      ^~~~~~~~
> > > >    In file included from include/linux/hardirq.h:7:0,
> > > >                     from include/linux/interrupt.h:11,
> > > >                     from arch/x86/kernel/traps.c:16:
> > > > >> include/linux/ftrace_irq.h:18:29: error: inlining failed in call to always_inline 'ftrace_nmi_exit': function attribute mismatch
> > > >     static __always_inline void ftrace_nmi_exit(void)
> > > >                                 ^~~~~~~~~~~~~~~
> > > >    In file included from include/linux/interrupt.h:11:0,
> > > >                     from arch/x86/kernel/traps.c:16:
> > > >    include/linux/hardirq.h:98:3: note: called from here
> > > >       ftrace_nmi_exit();    \
> > > >       ^~~~~~~~~~~~~~~~~
> > > >    arch/x86/kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> > > >      nmi_exit();
> > > >      ^~~~~~~~
> > > >    In file included from include/linux/preempt.h:78:0,
> > > >                     from include/linux/rcupdate.h:27,
> > > >                     from include/linux/rculist.h:11,
> > > >                     from include/linux/pid.h:5,
> > > >                     from include/linux/sched.h:14,
> > > >                     from include/linux/context_tracking.h:5,
> > > >                     from arch/x86/kernel/traps.c:15:
> > > >    arch/x86/include/asm/preempt.h:82:29: error: inlining failed in call to always_inline '__preempt_count_sub': function attribute mismatch
> > > >     static __always_inline void __preempt_count_sub(int val)
> > > >                                 ^~~~~~~~~~~~~~~~~~~
> > > >    In file included from include/linux/interrupt.h:11:0,
> > > >                     from arch/x86/kernel/traps.c:16:
> > > >    include/linux/hardirq.h:97:3: note: called from here
> > > >       __preempt_count_sub(NMI_OFFSET + HARDIRQ_OFFSET); \
> > > >       ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > > >    arch/x86/kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> > > >      nmi_exit();
> > > >      ^~~~~~~~
> > > > --
> > > >    In file included from include/linux/preempt.h:78:0,
> > > >                     from include/linux/rcupdate.h:27,
> > > >                     from include/linux/rculist.h:11,
> > > >                     from include/linux/pid.h:5,
> > > >                     from include/linux/sched.h:14,
> > > >                     from include/linux/context_tracking.h:5,
> > > >                     from arch/x86//kernel/traps.c:15:
> > > >    arch/x86//kernel/traps.c: In function 'do_int3':
> > > > >> arch/x86/include/asm/preempt.h:24:28: error: inlining failed in call to always_inline 'preempt_count': function attribute mismatch
> > > >     static __always_inline int preempt_count(void)
> > > >                                ^~~~~~~~~~~~~
> > > >    In file included from arch/x86/include/asm/current.h:5:0,
> > > >                     from include/linux/sched.h:12,
> > > >                     from include/linux/context_tracking.h:5,
> > > >                     from arch/x86//kernel/traps.c:15:
> > > >    include/linux/preempt.h:102:20: note: called from here
> > > >     #define in_nmi()  (preempt_count() & NMI_MASK)
> > > >                        ^~~~~~~~~~~~~~~
> > > >    include/linux/compiler.h:78:42: note: in definition of macro 'unlikely'
> > > >     # define unlikely(x) __builtin_expect(!!(x), 0)
> > > >                                              ^
> > > >    include/linux/hardirq.h:86:3: note: in expansion of macro 'BUG_ON'
> > > >       BUG_ON(in_nmi() == NMI_MASK);   \
> > > >       ^~~~~~
> > > >    include/linux/hardirq.h:86:10: note: in expansion of macro 'in_nmi'
> > > >       BUG_ON(in_nmi() == NMI_MASK);   \
> > > >              ^~~~~~
> > > >    arch/x86//kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> > > >      nmi_enter();
> > > >      ^~~~~~~~~
> > > >    In file included from include/linux/hardirq.h:7:0,
> > > >                     from include/linux/interrupt.h:11,
> > > >                     from arch/x86//kernel/traps.c:16:
> > > > >> include/linux/ftrace_irq.h:10:29: error: inlining failed in call to always_inline 'ftrace_nmi_enter': function attribute mismatch
> > > >     static __always_inline void ftrace_nmi_enter(void)
> > > >                                 ^~~~~~~~~~~~~~~~
> > > >    In file included from include/linux/interrupt.h:11:0,
> > > >                     from arch/x86//kernel/traps.c:16:
> > > >    include/linux/hardirq.h:85:3: note: called from here
> > > >       ftrace_nmi_enter();    \
> > > >       ^~~~~~~~~~~~~~~~~~
> > > >    arch/x86//kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> > > >      nmi_enter();
> > > >      ^~~~~~~~~
> > > >    In file included from include/linux/sched.h:12:0,
> > > >                     from include/linux/context_tracking.h:5,
> > > >                     from arch/x86//kernel/traps.c:15:
> > > > >> arch/x86/include/asm/current.h:13:44: error: inlining failed in call to always_inline 'get_current': function attribute mismatch
> > > >     static __always_inline struct task_struct *get_current(void)
> > > >                                                ^~~~~~~~~~~
> > > >    arch/x86/include/asm/current.h:18:17: note: called from here
> > > >     #define current get_current()
> > > >                     ^~~~~~~~~~~~~
> > > >    include/linux/lockdep.h:304:2: note: in expansion of macro 'current'
> > > >      current->lockdep_recursion += LOCKDEP_OFF; \
> > > >      ^~~~~~~
> > > >    include/linux/hardirq.h:84:3: note: in expansion of macro 'lockdep_off'
> > > >       lockdep_off();     \
> > > >       ^~~~~~~~~~~
> > > >    arch/x86//kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> > > >      nmi_enter();
> > > >      ^~~~~~~~~
> > > > >> arch/x86/include/asm/current.h:13:44: error: inlining failed in call to always_inline 'get_current': function attribute mismatch
> > > >     static __always_inline struct task_struct *get_current(void)
> > > >                                                ^~~~~~~~~~~
> > > >    arch/x86/include/asm/current.h:18:17: note: called from here
> > > >     #define current get_current()
> > > >                     ^~~~~~~~~~~~~
> > > >    include/linux/irqflags.h:40:2: note: in expansion of macro 'current'
> > > >      current->hardirq_context++;  \
> > > >      ^~~~~~~
> > > >    include/linux/hardirq.h:89:3: note: in expansion of macro 'trace_hardirq_enter'
> > > >       trace_hardirq_enter();    \
> > > >       ^~~~~~~~~~~~~~~~~~~
> > > >    arch/x86//kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> > > >      nmi_enter();
> > > >      ^~~~~~~~~
> > > >    In file included from include/linux/preempt.h:78:0,
> > > >                     from include/linux/rcupdate.h:27,
> > > >                     from include/linux/rculist.h:11,
> > > >                     from include/linux/pid.h:5,
> > > >                     from include/linux/sched.h:14,
> > > >                     from include/linux/context_tracking.h:5,
> > > >                     from arch/x86//kernel/traps.c:15:
> > > >    arch/x86/include/asm/preempt.h:77:29: error: inlining failed in call to always_inline '__preempt_count_add': function attribute mismatch
> > > >     static __always_inline void __preempt_count_add(int val)
> > > >                                 ^~~~~~~~~~~~~~~~~~~
> > > >    In file included from include/linux/interrupt.h:11:0,
> > > >                     from arch/x86//kernel/traps.c:16:
> > > >    include/linux/hardirq.h:87:3: note: called from here
> > > >       __preempt_count_add(NMI_OFFSET + HARDIRQ_OFFSET); \
> > > >       ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > > >    arch/x86//kernel/traps.c:521:2: note: in expansion of macro 'nmi_enter'
> > > >      nmi_enter();
> > > >      ^~~~~~~~~
> > > >    In file included from include/linux/preempt.h:78:0,
> > > >                     from include/linux/rcupdate.h:27,
> > > >                     from include/linux/rculist.h:11,
> > > >                     from include/linux/pid.h:5,
> > > >                     from include/linux/sched.h:14,
> > > >                     from include/linux/context_tracking.h:5,
> > > >                     from arch/x86//kernel/traps.c:15:
> > > > >> arch/x86/include/asm/preempt.h:24:28: error: inlining failed in call to always_inline 'preempt_count': function attribute mismatch
> > > >     static __always_inline int preempt_count(void)
> > > >                                ^~~~~~~~~~~~~
> > > >    In file included from arch/x86/include/asm/current.h:5:0,
> > > >                     from include/linux/sched.h:12,
> > > >                     from include/linux/context_tracking.h:5,
> > > >                     from arch/x86//kernel/traps.c:15:
> > > >    include/linux/preempt.h:102:20: note: called from here
> > > >     #define in_nmi()  (preempt_count() & NMI_MASK)
> > > >                        ^~~~~~~~~~~~~~~
> > > >    include/linux/compiler.h:78:42: note: in definition of macro 'unlikely'
> > > >     # define unlikely(x) __builtin_expect(!!(x), 0)
> > > >                                              ^
> > > >    include/linux/hardirq.h:96:3: note: in expansion of macro 'BUG_ON'
> > > >       BUG_ON(!in_nmi());    \
> > > >       ^~~~~~
> > > >    include/linux/hardirq.h:96:11: note: in expansion of macro 'in_nmi'
> > > >       BUG_ON(!in_nmi());    \
> > > >               ^~~~~~
> > > >    arch/x86//kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> > > >      nmi_exit();
> > > >      ^~~~~~~~
> > > >    In file included from include/linux/sched.h:12:0,
> > > >                     from include/linux/context_tracking.h:5,
> > > >                     from arch/x86//kernel/traps.c:15:
> > > > >> arch/x86/include/asm/current.h:13:44: error: inlining failed in call to always_inline 'get_current': function attribute mismatch
> > > >     static __always_inline struct task_struct *get_current(void)
> > > >                                                ^~~~~~~~~~~
> > > >    arch/x86/include/asm/current.h:18:17: note: called from here
> > > >     #define current get_current()
> > > >                     ^~~~~~~~~~~~~
> > > >    include/linux/irqflags.h:44:2: note: in expansion of macro 'current'
> > > >      current->hardirq_context--;  \
> > > >      ^~~~~~~
> > > >    include/linux/hardirq.h:94:3: note: in expansion of macro 'trace_hardirq_exit'
> > > >       trace_hardirq_exit();    \
> > > >       ^~~~~~~~~~~~~~~~~~
> > > >    arch/x86//kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> > > >      nmi_exit();
> > > >      ^~~~~~~~
> > > > >> arch/x86/include/asm/current.h:13:44: error: inlining failed in call to always_inline 'get_current': function attribute mismatch
> > > >     static __always_inline struct task_struct *get_current(void)
> > > >                                                ^~~~~~~~~~~
> > > >    arch/x86/include/asm/current.h:18:17: note: called from here
> > > >     #define current get_current()
> > > >                     ^~~~~~~~~~~~~
> > > >    include/linux/lockdep.h:309:2: note: in expansion of macro 'current'
> > > >      current->lockdep_recursion -= LOCKDEP_OFF; \
> > > >      ^~~~~~~
> > > >    include/linux/hardirq.h:99:3: note: in expansion of macro 'lockdep_on'
> > > >       lockdep_on();     \
> > > >       ^~~~~~~~~~
> > > >    arch/x86//kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> > > >      nmi_exit();
> > > >      ^~~~~~~~
> > > >    In file included from include/linux/hardirq.h:7:0,
> > > >                     from include/linux/interrupt.h:11,
> > > >                     from arch/x86//kernel/traps.c:16:
> > > > >> include/linux/ftrace_irq.h:18:29: error: inlining failed in call to always_inline 'ftrace_nmi_exit': function attribute mismatch
> > > >     static __always_inline void ftrace_nmi_exit(void)
> > > >                                 ^~~~~~~~~~~~~~~
> > > >    In file included from include/linux/interrupt.h:11:0,
> > > >                     from arch/x86//kernel/traps.c:16:
> > > >    include/linux/hardirq.h:98:3: note: called from here
> > > >       ftrace_nmi_exit();    \
> > > >       ^~~~~~~~~~~~~~~~~
> > > >    arch/x86//kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> > > >      nmi_exit();
> > > >      ^~~~~~~~
> > > >    In file included from include/linux/preempt.h:78:0,
> > > >                     from include/linux/rcupdate.h:27,
> > > >                     from include/linux/rculist.h:11,
> > > >                     from include/linux/pid.h:5,
> > > >                     from include/linux/sched.h:14,
> > > >                     from include/linux/context_tracking.h:5,
> > > >                     from arch/x86//kernel/traps.c:15:
> > > >    arch/x86/include/asm/preempt.h:82:29: error: inlining failed in call to always_inline '__preempt_count_sub': function attribute mismatch
> > > >     static __always_inline void __preempt_count_sub(int val)
> > > >                                 ^~~~~~~~~~~~~~~~~~~
> > > >    In file included from include/linux/interrupt.h:11:0,
> > > >                     from arch/x86//kernel/traps.c:16:
> > > >    include/linux/hardirq.h:97:3: note: called from here
> > > >       __preempt_count_sub(NMI_OFFSET + HARDIRQ_OFFSET); \
> > > >       ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > > >    arch/x86//kernel/traps.c:543:2: note: in expansion of macro 'nmi_exit'
> > > >      nmi_exit();
> > > >      ^~~~~~~~
> > > > ..
> > > >
> > > > vim +/try_get_desc +961 arch/x86/kernel/alternative.c
> > > >
> > > > 1f676247f36a4b Peter Zijlstra             2019-12-11  959
> > > > 809106a6157bce Thomas Gleixner            2020-01-21  960  static __always_inline
> > > > 809106a6157bce Thomas Gleixner            2020-01-21 @961  struct bp_patching_desc *try_get_desc(struct bp_patching_desc **descp)
> > > > 1f676247f36a4b Peter Zijlstra             2019-12-11  962  {
> > > > a9d380bd4091e7 Peter Zijlstra             2020-01-24  963     struct bp_patching_desc *desc = READ_ONCE_NOCHECK(*descp); /* rcu_dereference */
> > > > 1f676247f36a4b Peter Zijlstra             2019-12-11  964
> > > > a9d380bd4091e7 Peter Zijlstra             2020-01-24  965     if (!desc || !arch_atomic_inc_not_zero(&desc->refs))
> > > > 1f676247f36a4b Peter Zijlstra             2019-12-11  966             return NULL;
> > > > 1f676247f36a4b Peter Zijlstra             2019-12-11  967
> > > > 1f676247f36a4b Peter Zijlstra             2019-12-11  968     return desc;
> > > > 1f676247f36a4b Peter Zijlstra             2019-12-11  969  }
> > > > 1f676247f36a4b Peter Zijlstra             2019-12-11  970
> > > > 809106a6157bce Thomas Gleixner            2020-01-21 @971  static __always_inline void put_desc(struct bp_patching_desc *desc)
> > > > 1f676247f36a4b Peter Zijlstra             2019-12-11  972  {
> > > > 1f676247f36a4b Peter Zijlstra             2019-12-11  973     smp_mb__before_atomic();
> > > > a9d380bd4091e7 Peter Zijlstra             2020-01-24  974     arch_atomic_dec(&desc->refs);
> > > > 1f676247f36a4b Peter Zijlstra             2019-12-11  975  }
> > > > c0213b0ac03cf6 Daniel Bristot de Oliveira 2019-06-12  976
> > > >
> > > > :::::: The code at line 961 was first introduced by commit
> > > > :::::: 809106a6157bce0fff76bfc7864e7ce34080abe0 x86/int3: Ensure that poke_int3_handler() is not traced
> > > >
> > > > :::::: TO: Thomas Gleixner <tglx@linutronix.de>
> > > > :::::: CC: Peter Zijlstra <peterz@infradead.org>
> > > >
> > > > ---
> > > > 0-DAY CI Kernel Test Service, Intel Corporation
> > > > https://lists.01.org/hyperkitty/list/kbuild-all@lists.01.org
> > >
> > >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BayJrm6ZrkQwybGZniP-xwtxjkmMpYVdCoU4mKzDUWydQ%40mail.gmail.com.
