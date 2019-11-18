Return-Path: <kasan-dev+bncBCMIZB7QWENRBA4OZPXAKGQEOPNNXLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 41546100939
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Nov 2019 17:29:57 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id m1sf14496269pfh.5
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Nov 2019 08:29:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574094595; cv=pass;
        d=google.com; s=arc-20160816;
        b=O6Iti1fQxarrmCEQ2MbKC9PfW9M99yK10a5d+sj8aEbWNdmYzTtEQIdwwSQu7DGdV0
         H5zINii0mCrO/vj0H7tEMhhcUgiW9Z46Mf5QlHWiAxnuXQZRfwBIMn63E9n7SDT762kl
         3JJzMvG8iLzZatL/MPNd/oPkIR6Jf6cVgVXDvKpUX6BgpXKpIvW8y7niQTZyjLAnYRlc
         V67oiB4qcamKH0q3Ap0KveJraQBT7uixvYhmFSQvC3uHwZTyAxTbVd+9AL7JsNhGGeR1
         E2tEbAiZzEbxKLVmL7VgvXaKK99Y1Cgl8NeA+8c3gF8YgfAg2ZCC1lJDYgURe78CkNsA
         qHqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=u8eUHgLn5djDBCVur2ZUJ0UAwNIbZ4frwOOUGbCA84s=;
        b=MHoM0wXL5+ZKM9vx1m/Q47D5wQNyG3sdzHdJfLGsm/px+weTA7jUy9PQnnCUZwvOoT
         uMZxiQmrpvkdb8jHI159bMquoSudBbhuKH/XcpcRHdRhrja6TTXc8bNexdAIP6Dt5rRT
         sEPBTGzUoUNPSjh9ac3glu1jfnTMz9Y5K84cK3dz9BeyfiEPXs00FyVlBp+xgjlEsuQy
         /SQ8YKamo+xve67TlzmRBpjA/kmXEPk2KZhrRfelHAyjyKjl1Dto+5zf/v9vEvGSOYmr
         +UsjagRBoSFER3/YmmAQ1Pq+P/PD3jZ1HlknKvr91+tcI78SlcUScwMz7K4WzGg7ltiH
         wvNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Pt744SvN;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=u8eUHgLn5djDBCVur2ZUJ0UAwNIbZ4frwOOUGbCA84s=;
        b=s3V9mSOiULPbAbXqhtAa9Gw6aNO2OUsMPLzVFvWO0HCwyJtZpaL0F2eKIidpm1x/K+
         7SjlDPGDyeTXc3JGeoFAm9ZN7j7Ib5VnqLTJQr6JQ1/68effQe3kSZuTDpM7fZR/dwoJ
         Pj0ZVCTCFveBgoDWjQp4JfIno5pYpYwPYm/tCnTSioNWbo+hZtYmhW1KoHuArciEdBgH
         ttS3S1aGj8dAzTS3u1jG7hCYNssbkQJWOmwAlGBWh9pyrqQF7U1qyruYXw8AKe9G6zCu
         q1JDEye9k6MyOVbN56JjiR6cGFKOwVPotq1c8o82otNbkfDGjDFZth37+NGYJWZ+rii3
         9GJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=u8eUHgLn5djDBCVur2ZUJ0UAwNIbZ4frwOOUGbCA84s=;
        b=KQ10smvrzdaEYGSrLWUdSPChEenD9y1lyXM8KcmieqvoT0YPXPq+739bOjtYlHS766
         nQCWiPi45M8pD7uA8mpsN0BhOtHZQ+3jDo+PS9XVyNMdA5iarPo576HnT+DNQon1Aq8v
         mSQH2z0gLBdHe0zKl4G78fnqZPjLsGFt/EQSaIVJ4ROBp/n0t2UUmzoYPXkMAXy3m9Tw
         iVpGuQp9lTtbCg4OtRiAp0XEagVRgUTSVPYzlrn1+13pEpDIaEEIH/gOwccbLTge/4BG
         1UjjC1ocZvS+2YpFpf/Ht4mxwFdfWnK29WC00xvVWyxGYSVAtRRurOSoGnvcqWD1ldmi
         kNPg==
X-Gm-Message-State: APjAAAUBn6cXdVSxZo8OloKcEYq5leAryjjwzwugeD5cM7x1Tak6aQGY
	EKbKI32gjEUKEUz3xyFdWP8=
X-Google-Smtp-Source: APXvYqzW9t/j21l+tA6chST+F2CBxdoX++EEs5KE+oGAZvcumQDbR8Z7LoPsyN46/KqRSP0c9XB0Uw==
X-Received: by 2002:a17:902:7c07:: with SMTP id x7mr30157116pll.124.1574094595259;
        Mon, 18 Nov 2019 08:29:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:860b:: with SMTP id p11ls4056766pfn.16.gmail; Mon, 18
 Nov 2019 08:29:54 -0800 (PST)
X-Received: by 2002:a63:8749:: with SMTP id i70mr170116pge.364.1574094594831;
        Mon, 18 Nov 2019 08:29:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574094594; cv=none;
        d=google.com; s=arc-20160816;
        b=MwKwzvumWFq2dODvx3yhMrl8qaftZkPonxNbv9yOi4w7acUEDhmVK1/Sa0a5JByUIm
         eUsrcGJQHyxLuab4VrZwptmMRNQcdJLoaOM0AcN2PJ7ZFXUnvBhYr31+3q6ORurA2wV9
         LKk80YznTYisPIiu9kcZKmooQj86R1S66wZL1EskdeIybETmpj7p7xtDkNNkdSTQF3CL
         1tEuw9ETPBxhQ0tMYruQDFCKosnnb4jbjPnRbv/DLfarIC1H6FYqLNcPfRMPXKEiPFI8
         fENfMw+9rlmndc3cr0zyJDbsH76t4NDxD7uwHsvrJGcTVcszW1Fq3+lvpMxu3TRDaV49
         QAew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EWpMW0feycxyW1VyPAp6s2ygtKt8fZ0jnVixWgUidTo=;
        b=T66r1+r0cNr7cCK1+iDeWMjqGugXrTzm2GH7ZmajPFjaWprOlmYzyJL/izlpPJ12ST
         TXt3D4VoOutiECUGnZEkXSnRhxPyGpGwDkQMmrzfzLEg1OeDIEm62zfJJROZGbLorVNs
         GLCQpnZNCQpva7wOWN4MqIGoQ/X51CXe5hzmavHF1i0rb6SK+jXH9+eHEpO80By+QJPA
         9YyVQuGj7UvDMZ8ZVal5mXUbIa64rnK+FXcHbzg/2ou2NRHvguM1aTpsIExAQdfMcYWc
         +ic7SYAwkH70C4MqCz/U50MiIZ8E7dRTACfnd1U6XDathYKps1Gl9/KWwTOLk7FlG0jW
         bZjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Pt744SvN;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf43.google.com (mail-qv1-xf43.google.com. [2607:f8b0:4864:20::f43])
        by gmr-mx.google.com with ESMTPS id n2si897435pgq.0.2019.11.18.08.29.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Nov 2019 08:29:54 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) client-ip=2607:f8b0:4864:20::f43;
Received: by mail-qv1-xf43.google.com with SMTP id d3so6773643qvs.11
        for <kasan-dev@googlegroups.com>; Mon, 18 Nov 2019 08:29:54 -0800 (PST)
X-Received: by 2002:a05:6214:8ee:: with SMTP id dr14mr27167149qvb.122.1574094593379;
 Mon, 18 Nov 2019 08:29:53 -0800 (PST)
MIME-Version: 1.0
References: <20191115191728.87338-1-jannh@google.com> <20191115191728.87338-2-jannh@google.com>
 <20191118142144.GC6363@zn.tnic> <CACT4Y+bCOr=du1QEg8TtiZ-X6U+8ZPR4N07rJOeSCsd5h+zO3w@mail.gmail.com>
 <CAG48ez1AWW7FkvU31ahy=0ZiaAreSMz=FFA0u8-XkXT9hNdWKA@mail.gmail.com>
In-Reply-To: <CAG48ez1AWW7FkvU31ahy=0ZiaAreSMz=FFA0u8-XkXT9hNdWKA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 18 Nov 2019 17:29:42 +0100
Message-ID: <CACT4Y+bfF86YY_zEGWO1sK0NwuYgr8Cx0wFewRDq0WL_GBgO0Q@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] x86/traps: Print non-canonical address on #GP
To: Jann Horn <jannh@google.com>
Cc: Borislav Petkov <bp@alien8.de>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Sean Christopherson <sean.j.christopherson@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Pt744SvN;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43
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

On Mon, Nov 18, 2019 at 5:20 PM 'Jann Horn' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Mon, Nov 18, 2019 at 5:03 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > On Mon, Nov 18, 2019 at 3:21 PM Borislav Petkov <bp@alien8.de> wrote:
> > >
> > > On Fri, Nov 15, 2019 at 08:17:27PM +0100, Jann Horn wrote:
> > > >  dotraplinkage void
> > > >  do_general_protection(struct pt_regs *regs, long error_code)
> > > >  {
> > > > @@ -547,8 +581,15 @@ do_general_protection(struct pt_regs *regs, long error_code)
> > > >                       return;
> > > >
> > > >               if (notify_die(DIE_GPF, desc, regs, error_code,
> > > > -                            X86_TRAP_GP, SIGSEGV) != NOTIFY_STOP)
> > > > -                     die(desc, regs, error_code);
> > > > +                            X86_TRAP_GP, SIGSEGV) == NOTIFY_STOP)
> > > > +                     return;
> > > > +
> > > > +             if (error_code)
> > > > +                     pr_alert("GPF is segment-related (see error code)\n");
> > > > +             else
> > > > +                     print_kernel_gp_address(regs);
> > > > +
> > > > +             die(desc, regs, error_code);
> > >
> > > Right, this way, those messages appear before the main "general
> > > protection ..." message:
> > >
> > > [    2.434372] traps: probably dereferencing non-canonical address 0xdfff000000000001
> > > [    2.442492] general protection fault: 0000 [#1] PREEMPT SMP
> > >
> > > Can we glue/merge them together? Or is this going to confuse tools too much:
> > >
> > > [    2.542218] general protection fault while derefing a non-canonical address 0xdfff000000000001: 0000 [#1] PREEMPT SMP
> > >
> > > (and that sentence could be shorter too:
> > >
> > >         "general protection fault for non-canonical address 0xdfff000000000001"
> > >
> > > looks ok to me too.)
> >
> > This exact form will confuse syzkaller crash parsing for Linux kernel:
> > https://github.com/google/syzkaller/blob/1daed50ac33511e1a107228a9c3b80e5c4aebb5c/pkg/report/linux.go#L1347
> > It expects a "general protection fault:" line for these crashes.
> >
> > A graceful way to update kernel crash messages would be to add more
> > tests with the new format here:
> > https://github.com/google/syzkaller/tree/1daed50ac33511e1a107228a9c3b80e5c4aebb5c/pkg/report/testdata/linux/report
> > Update parsing code. Roll out new version. Update all other testing
> > systems that detect and parse kernel crashes. Then commit kernel
> > changes.
>
> So for syzkaller, it'd be fine as long as we keep the colon there?
> Something like:
>
> general protection fault: derefing non-canonical address
> 0xdfff000000000001: 0000 [#1] PREEMPT SMP

Probably. Tests help a lot to answer such questions ;) But presumably
it should break parsing.

> And it looks like the 0day test bot doesn't have any specific pattern
> for #GP, it seems to just look for the panic triggered by
> panic-on-oops as far as I can tell (oops=panic in lkp-exec/qemu, no
> "general protection fault" in etc/dmesg-kill-pattern).
>
> > An unfortunate consequence of offloading testing to third-party systems...
>
> And of not having a standard way to signal "this line starts something
> that should be reported as a bug"? Maybe as a longer-term idea, it'd
> help to have some sort of extra prefix byte that the kernel can print
> to say "here comes a bug report, first line should be the subject", or
> something like that, similar to how we have loglevels...

This would be great.
Also a way to denote crash end.
However we have lots of special logic for subjects, not sure if kernel
could provide good subject:
https://github.com/google/syzkaller/blob/1daed50ac33511e1a107228a9c3b80e5c4aebb5c/pkg/report/linux.go#L537-L1588
Probably it could, but it won't be completely trivial. E.g. if there
is a stall inside of a timer function, it should give the name of the
actual timer callback as identity ("stall in timer_subsystem_foo"). Or
for syscalls we use more disambiguation b/c "in sys_ioclt" is not much
different than saying "there is a bug in kernel" :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbfF86YY_zEGWO1sK0NwuYgr8Cx0wFewRDq0WL_GBgO0Q%40mail.gmail.com.
