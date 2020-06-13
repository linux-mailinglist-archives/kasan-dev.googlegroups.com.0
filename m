Return-Path: <kasan-dev+bncBCMIZB7QWENRBW4XST3QKGQECM3QAQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id 77A1E1F8468
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Jun 2020 19:24:44 +0200 (CEST)
Received: by mail-vk1-xa40.google.com with SMTP id t5sf3337685vkk.11
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Jun 2020 10:24:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592069083; cv=pass;
        d=google.com; s=arc-20160816;
        b=RvWrp+V0wCSJ6blbcmprhJcpGzzIevj5XBSOEDVop3Jw+N8wDSK83hHPCZfCsWdp0O
         2lda9+Uw/3ABPG3d7IOxdoNG/wCukSVFQMK9nVmxVC+tbg8Ul9RJQ5uwoivEvOPB3ik+
         Ji4XbiO11R80FQeNj8dSGQjtchBVscYjHL43jLBOsmJM7khicP1iQQy04TcrnHYhnTjM
         XCpJAhmpxhxLOKoDeA47KfOSfPX90ixO+hjPaZhQcrzIkDpRXIpv7iLgjQddJKgpRY+E
         0gNPEo/n6JbGfaUqc/zXPPE5sMuKwPm3eYHUCZnpXZQCTKv6Al6c7FfNj91+BftOVt0B
         +Pgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zJusZNHCs8Jp2Lk6HDis5crwj2IINOJuK0Sl+hxRiXA=;
        b=yojPT5jW1UiAH+H/pWLNtDqpovuW3wNCc/XbLTU0T9/6yHGQAkeIuhBlIFi/FCvI47
         mVwBW+0czrPh9XfwV86JHBjA/P5iWb1FDGZc6opvxFULIPlDa0B8eez4ze0tkpbeUGu0
         jl3qF634O6Ds6LY4TltOXjvXkiqjbh+YBInAfM5tvwCS43DguO1PGyNiSOn1R9vtBSpK
         b0U8k+jlegSM6t9pQ+luxmeGrm4UrY/B4aqZ8SADpNegW4z4nucB0BofRvUW4pEDp7NQ
         AGLCEtbserIvbB4WpQ3tof+nAwS+yqM9vkrQk4whM9LLRiSmB1OpXHpLoWxRiX5KErI5
         GfYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=my06dzPh;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zJusZNHCs8Jp2Lk6HDis5crwj2IINOJuK0Sl+hxRiXA=;
        b=ePs3dIe+X9LvEa6kgzcVAciTgyZvfF8wnQJCrkx02u1qFp65TwY44Folk8ndLggDoN
         U8J4ttDxYqeDJo8efbGWdHJ3it5Yi1HDiTb4OKxmTwqPdllOClYtxpsxAbgmXUoHKYg8
         VoRMQ2Dw7dbeDY2t8GELd0nhU/3NYm2AeSHb/rJ+++u0dXh2DGM1/8KGK4JzHY0zNeoo
         kld/QlLCybK/ZHhK8gyeRCYsT0fDaWRfA7BvGHAhhVGJGmAz1BS0PEY9ufaf7MAMfP55
         A3qBjlFF6wrk8255Mk2zxATJT754rkUPHQsxzo43+X0Z2o3QtPtwx8DRycqCDmeqiv3o
         JGPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zJusZNHCs8Jp2Lk6HDis5crwj2IINOJuK0Sl+hxRiXA=;
        b=MSztjriO/Edb7Jnsuu2tXtt844mi7LsKu/hPng2iwGt1xSB5/hAebb0MMAz1mkye5F
         om+cfbMCH7vr+PzDqwo9hCmI9YoodKChrwsU9u+1T57dHiJu9ums7+J/m1W3T0ivrvxr
         IvTYUJIyttQXZf5PbOifi6dsac83MKpOZOR+dcO8KGgI/+4BEcjfQFBPAEfKeCuuxzPe
         OZbzVf28KVNWfORMfUNuWLGPHjo9fSoNAlqbDI0qpL5IwlKmQBdxa3Kke5//IwcP+4T7
         EuLMq4Dqo0MIWgVdlzPDug9nXoUrUAcWTek54QHsUQ/+joXccGD/GggmBTkq+E7mFCXI
         Oe5A==
X-Gm-Message-State: AOAM5313SRApzMtboHPSB7YGPHTqeCHr5FgA3iIATkMWRkIEq+Aki1i3
	L1QvTjeq3l3qg1yKRtQeYWk=
X-Google-Smtp-Source: ABdhPJxEDxx7QOGi40I5oM69bfo6tfi13Z0ZQZOsp/m7Z6WX5DROWnlp0rKMpLmK2xKlvip+pxICJQ==
X-Received: by 2002:a05:6102:3098:: with SMTP id l24mr13047810vsb.86.1592069083138;
        Sat, 13 Jun 2020 10:24:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:8717:: with SMTP id j23ls1022117vsd.11.gmail; Sat, 13
 Jun 2020 10:24:42 -0700 (PDT)
X-Received: by 2002:a67:2c4c:: with SMTP id s73mr14746261vss.233.1592069082689;
        Sat, 13 Jun 2020 10:24:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592069082; cv=none;
        d=google.com; s=arc-20160816;
        b=xlQQFpRXZEczr9JUhkl26VCIGvKvT2U2eeFRLiIZfzaeXBde1F762ohfKV3inVkYWs
         SjN4z60ywvi/ZSGRuj4vLPrMJBIJBCr072ca4JI5NJdGVql/dwQ/6myWOxZsBB7Tgb2a
         k3sDqpqu+GwIZOk6hDhTqutGMlzoi4GWPF77CbiKKVf50dBzFCoySARfCJWs/WELBb8M
         c7PQVzliK/WiWj4leLCWgUh3MvEZGuOG427RjEnVJeXfWt28w2sRhPWyt98qegJ6xSmh
         hlnsiEGwiAUloQZ/ZrSskPFXmSJO2jXbWyx+YF3ieabOus2W5ZzdajVe3SGprSRlBFnG
         6niQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Cf1LQ5fNlVaS52D8jPent3DcteJDu/0EEO4v1tjBzHI=;
        b=ARg2PNxhGQ/W/0N5f52i2woRklg7aAW9+E6+M3Owf8Jljmwjp2GKJmf2KU8I50OE1K
         5H04j7gHiT+ijpdh1KGjoTDyeJwmaZOVifoM2N4l/gNlqJYGrFMB8/JQb4mET+7jF1+N
         z5azSc1Vn3gispPwNCQQkzaJQlkt8w+vueIiCrV26RwAgz7wi4UJw8EykoQ1LE3A1zG9
         sJ9bT7cwdsdcfLhcBk2MjG8oPtzDq5KI4Kfok8YsK1WD0BV8U4wckPjouP0b9/srcGnx
         bG6AKS2v5+L9Fv8uSw4pOFMWZvw4eWIeb3q0EPf7mLA48M5+7RyjElRvPuUzWhovPX68
         3VFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=my06dzPh;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id t9si639808vkb.1.2020.06.13.10.24.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 13 Jun 2020 10:24:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id c14so11985626qka.11
        for <kasan-dev@googlegroups.com>; Sat, 13 Jun 2020 10:24:42 -0700 (PDT)
X-Received: by 2002:a05:620a:786:: with SMTP id 6mr7223882qka.407.1592069081942;
 Sat, 13 Jun 2020 10:24:41 -0700 (PDT)
MIME-Version: 1.0
References: <20200605082839.226418-1-elver@google.com> <CACT4Y+ZqdZD0YsPHf8UFJT94yq5KGgbDOXSiJYS0+pjgYDsx+A@mail.gmail.com>
 <20200605120352.GJ3976@hirez.programming.kicks-ass.net> <CAAeHK+zErjaB64bTRqjH3qHyo9QstDSHWiMxqvmNYwfPDWSuXQ@mail.gmail.com>
 <CACT4Y+Zwm47qs8yco0nNoD_hFzHccoGyPznLHkBjAeg9REZ3gA@mail.gmail.com>
 <CANpmjNPNa2f=kAF6c199oYVJ0iSyirQRGxeOBLxa9PmakSXRbA@mail.gmail.com>
 <CACT4Y+Z+FFHFGSgEJGkd+zCBgUOck_odOf9_=5YQLNJQVMGNdw@mail.gmail.com>
 <20200608110108.GB2497@hirez.programming.kicks-ass.net> <20200611215538.GE4496@worktop.programming.kicks-ass.net>
 <CACT4Y+aKVKEp1yoBYSH0ebJxeqKj8TPR9MVtHC1Mh=jgX0ZvLw@mail.gmail.com> <20200612114900.GA187027@google.com>
In-Reply-To: <20200612114900.GA187027@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 13 Jun 2020 19:24:29 +0200
Message-ID: <CACT4Y+bBtCbEk2tg60gn5bgfBjARQFBgtqkQg8VnLLg5JwyL5g@mail.gmail.com>
Subject: Re: [PATCH -tip v3 1/2] kcov: Make runtime functions noinstr-compatible
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=my06dzPh;       spf=pass
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

On Fri, Jun 12, 2020 at 1:49 PM Marco Elver <elver@google.com> wrote:
> On Fri, 12 Jun 2020, Dmitry Vyukov wrote:
>
> > On Thu, Jun 11, 2020 at 11:55 PM Peter Zijlstra <peterz@infradead.org> wrote:
> > >
> > > On Mon, Jun 08, 2020 at 01:01:08PM +0200, Peter Zijlstra wrote:
> > > > On Mon, Jun 08, 2020 at 09:57:39AM +0200, Dmitry Vyukov wrote:
> > > >
> > > > > As a crazy idea: is it possible to employ objtool (linker script?) to
> > > > > rewrite all coverage calls to nops in the noinstr section? Or relocate
> > > > > to nop function?
> > > > > What we are trying to do is very static, it _should_ have been done
> > > > > during build. We don't have means in existing _compilers_ to do this,
> > > > > but maybe we could do it elsewhere during build?...
> > > >
> > > > Let me try and figure out how to make objtool actually rewrite code.
> > >
> > > The below is quite horrific but seems to sorta work.
> > >
> > > It turns this:
> > >
> > >   12:   e8 00 00 00 00          callq  17 <lockdep_hardirqs_on+0x17>
> > >                         13: R_X86_64_PLT32      __sanitizer_cov_trace_pc-0x4
> > >
> > > Into this:
> > >
> > >   12:   90                      nop
> > >   13:   90                      nop
> > >                         13: R_X86_64_NONE       __sanitizer_cov_trace_pc-0x4
> > >   14:   90                      nop
> > >   15:   90                      nop
> > >   16:   90                      nop
> > >
> > >
> > > I'll have to dig around a little more to see if I can't get rid of the
> > > relocation entirely. Also, I need to steal better arch_nop_insn() from
> > > the kernel :-)
> >
> > Wow! Cool!
> > Thanks for resolving this. I guess this can be used to wipe more
> > unwanted things in future :)
> >
> > Marco double checked and his patch did not actually fix the existing
> > crash under KCSAN. The call itself was the problem or something,
> > returning early did not really help. This should hopefully fix it.
> > Marco, please double check.
> >
> > Re better nop insn, I don't know how much work it is (or how much you
> > are striving for perfection :)). But from KCOV point of view, I think
> > we can live with more or less any nop insn. The main thing was
> > removing overhead from all other (not noinstr) cases, I would assume
> > the noinstr cases where we use nops are very rare. I mean don't spend
> > too much time on it, if it's not needed for something else.
> >
> > Thanks again!
>
> This is great, thanks! To make noinstr not call into KCOV, this
> definitely seems to do the job.
>
> Though sadly it doesn't fix the problem I'm seeing. The problem occurs
> when I compile using Clang, and enable either KASAN or KCSAN together
> with KCOV. Actually, turning off KCOV also shows this... a stacktrace is
> below.

I can't reproduce this after tuning off KCOV. Just KASAN works for me.
Also the following helps (at least for my config):

diff --git a/lib/Makefile b/lib/Makefile
index b1c42c10073b9..8514519bc5bcb 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -17,6 +17,7 @@ KCOV_INSTRUMENT_list_debug.o := n
 KCOV_INSTRUMENT_debugobjects.o := n
 KCOV_INSTRUMENT_dynamic_debug.o := n
 KCOV_INSTRUMENT_fault-inject.o := n
+KCOV_INSTRUMENT_smp_processor_id.o := n


Btw, do you use inline instrumentation for KASAN or outline?
I use inline KASAN, so maybe it's a function call that's the problem.
KCOV uses calls and KCSAN also uses calls.

And it's not that we are getting that "BUG:", right? Otherwise we
would see it in non-KCOV builds as well. So it must be something in
the very beginning of the function...




> The repro is this one: https://syzkaller.appspot.com/x/repro.c?x=1017ef06100000
>
> I don't quite understand what's going on here. Maybe the inserted
> instrumentation causes the compiler to spill more things onto the stack
> and somehow blow that? The nops obviously won't help with that. :-/
>
> I'll try to debug and understand this some more. Also this is of course
> on top of:
> https://lore.kernel.org/lkml/20200604102241.466509982@infradead.org/
>
> But, again, for disabling KCOV instrumentation in noinstr, I believe
> your patch does what we want. In future, when we get compiler support
> for __no_sanitize_coverage, the logic you're adding to objtool can
> probably stay but shouldn't be invoked if the compiler is doing its job.
>
> Thanks,
> -- Marco
>
> ------ >8 ------
>
> traps: PANIC: double fault, error_code: 0x0
> double fault: 0000 [#1] PREEMPT SMP PTI
> CPU: 3 PID: 513 Comm: a.out Not tainted 5.7.0+ #1
> Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
> RIP: 0010:native_save_fl arch/x86/include/asm/irqflags.h:29 [inline]
> RIP: 0010:arch_local_save_flags arch/x86/include/asm/irqflags.h:79 [inline]
> RIP: 0010:check_preemption_disabled+0x60/0x120 lib/smp_processor_id.c:19
> Code: 7f 74 27 90 90 90 90 90 65 48 8b 04 25 28 00 00 00 48 3b 44 24 08 0f 85 c6 00 00 00 89 d8 48 83 c4 10 5b 41 5c 41 5e 41 5f c3 <9c> 8f 04 24 f7 04 24 00 02 00 00 75 07 90 90 90 90 90 eb ca 65 4c
> RSP: 0018:fffffe0000094ff8 EFLAGS: 00010046
> RAX: 0000000080000000 RBX: 0000000000000003 RCX: ffffffffacc00ef7
> RDX: 0000000000000000 RSI: ffffffffad29c4f2 RDI: ffffffffad21fe08
> RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
> R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
> R13: 0000000000000000 R14: ffffffffad29c4f2 R15: ffffffffad21fe08
> FS:  0000000001d26880(0000) GS:ffffa16e5fcc0000(0000) knlGS:0000000000000000
> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> CR2: fffffe0000094fe8 CR3: 00000008147bc002 CR4: 0000000000760ee0
> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> PKRU: 55555554
> Call Trace:
>  <ENTRY_TRAMPOLINE>
>  __this_cpu_preempt_check+0x18/0x1a lib/smp_processor_id.c:65
>  fixup_bad_iret+0x2e/0xe0 arch/x86/kernel/traps.c:678
>  error_entry+0xd5/0xe0 arch/x86/entry/entry_64.S:937
> RIP: 0010:native_irq_return_iret+0x0/0x2
> Code: 5d 41 5c 5d 5b 41 5b 41 5a 41 59 41 58 58 59 5a 5e 5f 48 83 c4 08 eb 0b 66 66 2e 0f 1f 84 00 00 00 00 00 f6 44 24 20 04 75 02 <48> cf 57 0f 01 f8 66 90 0f 20 df 48 0f ba ef 3f 48 81 e7 ff e7 ff
> RSP: 0018:fffffe00000951d8 EFLAGS: 00010046 ORIG_RAX: 0000000000000000
> RAX: 0000000000000000 RBX: 0000000000000000 RCX: 0000000000000000
> RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000020000100
> RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
> R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
> R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
> RIP: 0033:0x3bfd19e0df38d197
> Code: Bad RIP value.
> RSP: 002b:00007ffd10c4c948 EFLAGS: 00000313 </ENTRY_TRAMPOLINE>
> Modules linked in:
> ---[ end trace df1b33281490ebc3 ]---
> RIP: 0010:native_save_fl arch/x86/include/asm/irqflags.h:29 [inline]
> RIP: 0010:arch_local_save_flags arch/x86/include/asm/irqflags.h:79 [inline]
> RIP: 0010:check_preemption_disabled+0x60/0x120 lib/smp_processor_id.c:19
> Code: 7f 74 27 90 90 90 90 90 65 48 8b 04 25 28 00 00 00 48 3b 44 24 08 0f 85 c6 00 00 00 89 d8 48 83 c4 10 5b 41 5c 41 5e 41 5f c3 <9c> 8f 04 24 f7 04 24 00 02 00 00 75 07 90 90 90 90 90 eb ca 65 4c
> RSP: 0018:fffffe0000094ff8 EFLAGS: 00010046
> RAX: 0000000080000000 RBX: 0000000000000003 RCX: ffffffffacc00ef7
> RDX: 0000000000000000 RSI: ffffffffad29c4f2 RDI: ffffffffad21fe08
> RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
> R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
> R13: 0000000000000000 R14: ffffffffad29c4f2 R15: ffffffffad21fe08
> FS:  0000000001d26880(0000) GS:ffffa16e5fcc0000(0000) knlGS:0000000000000000
> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> CR2: fffffe0000094fe8 CR3: 00000008147bc002 CR4: 0000000000760ee0
> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> PKRU: 55555554

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbBtCbEk2tg60gn5bgfBjARQFBgtqkQg8VnLLg5JwyL5g%40mail.gmail.com.
