Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBO4JZPXAKGQESFSRNQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2371110090F
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Nov 2019 17:20:13 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id l63sf16621731ili.17
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Nov 2019 08:20:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574094012; cv=pass;
        d=google.com; s=arc-20160816;
        b=eEnxT53adH3ordUlfcFLsXcoMeOO/TjAMWv6MOTxgQeZXv3OpxXXhaKhAKPrPizkFI
         +IWHqPzd2OFLopm7wpMFq2PoFBNfjM5zHk23dXx2y6UryX8aLm2wlCVMj9XwcjMRn/b+
         ZjSy67RLQ8OAF/0Uxdc1XHHkS3ThlVrmS4zPuIOnWueJKQplygmhXOJXMIox4Ufy2tb8
         Yq9DYa7/TIpryCSVidCxKgOEok+oP2Ja0uTj3yrjqkPsfzsh5yeH0KA7ZBwH6MA3EBDA
         oALZFxOZbY2Hqx6X97/3EoIppAb2TcNzv/kemt54CWnMB82UtmxejvwpyY+PiRy3x8EE
         hwEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2sk4+yzaQyeLy/B96d+AmN9qyxa7X668g1YpVxERTd0=;
        b=Ig+0e8Pr5pJ3ojthbbkWfhMjvM8atyH2SqHg94CSaWtb7M/4mqmpjzRPCHZI/x5JkK
         S6yL7miC7TuiFZ0S3/2bCvJYXXF3Ps0AxkH7A0AdH6rxC6yZ5nSsMouxwC4abS1fcutM
         zHj+oxxmbcsMv7d63iJGgcPCloDWgUh2fSgq2t11qLyU5aa6lnkR/u48kA+JQ4v3KUln
         UyIOFzQUD586Q/CmKjYsovoey0tl7RLGORgc6cUuc5Y+yAhvpEQD6bFEU1fOZ05Imbmu
         7EMOfx2zx7MU18u/35iAq7aiDzNqs1F5oNOUjFcyfz4sFB0OHkoqs4rIxmlIkvjTvrG+
         DXsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="PO0SsL/c";
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2sk4+yzaQyeLy/B96d+AmN9qyxa7X668g1YpVxERTd0=;
        b=MNkCDD3dGxlUS0hbUILhjDwnH86x43SQhC/p3qotra7Tpn08FGZu/fXt56WLcQvxny
         deCJQaHUhBqNxzWrrfrHzof3/kKf7GkbmwRghxk4VOBI0973QqmleIz19ErtSKzA9ewc
         4MW0NcDcikdwaapD9PQq+CVm2WCEwfoOIOGeHiOoeYNVNodQ9L8ighZBTaMMd6g4OtNj
         ZMItYGLkHZkwcZmzBdZbS0ULK3krjKTX4h6QgVrMT1+FbcAfja5ak/2ijY53s5lZn2IV
         WLn8r4sBGFKXM/P+UJm29m2WB42GlN2zjPh9RSsI2PdI3GaeGVVxQ1nWXlAZpc9oHoMU
         9q2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2sk4+yzaQyeLy/B96d+AmN9qyxa7X668g1YpVxERTd0=;
        b=T+x6iGJ4JKL+/NCkD7emTFRhFn/E9Bpwp1PTrFMA10vkNvy3VK6xoeAKps2F5k8CKL
         Z/yUmgumi96yFsyL9C8wfHVsZutkbFsd025h3GB70rHgrKCEmgzW2awgCJSNchEZ2XAF
         cVNQZVBw6GuuSXJ+VsvM2wQLpWq9tCBUmy+a2i96eVYPk+MlLZNLUScDZCdfLnCHvlDK
         TDsCLRnUswRMiZ1g72Zy1lFOEzR+VcFjdhr5youEEnBKTDMjiPDguT00uSeg+JbOusyW
         nLggs499vcVwdNO/NjIcqqTZHK7vXpNtfx1Z6MjmYH66OBtO7jPyXtXUQIf4vmsI2aNj
         3iig==
X-Gm-Message-State: APjAAAXVOTBjhGYpa3eIFyPtIFajtXDoC7xrEprTKtXDGrHG6AvgBsFd
	vuFw447jsTkQ8BfewnVqiBI=
X-Google-Smtp-Source: APXvYqyFbLDV/NFYYje50oT9r9lrW8+nlCrXeLwX446aPA0a3t2+fYWSychSgwRD42uDSdxIBitdIw==
X-Received: by 2002:a92:7405:: with SMTP id p5mr17440306ilc.261.1574094011957;
        Mon, 18 Nov 2019 08:20:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:1912:: with SMTP id 18ls3216011ilz.4.gmail; Mon, 18 Nov
 2019 08:20:11 -0800 (PST)
X-Received: by 2002:a92:458b:: with SMTP id z11mr16365934ilj.216.1574094011520;
        Mon, 18 Nov 2019 08:20:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574094011; cv=none;
        d=google.com; s=arc-20160816;
        b=jmo+h6crgmx+WD3qniPrAo7p+i9YZuer93gyLwXbjb6CU0ju5Tbdp5R3mL0RLh7bC8
         VejxT2gVMulTSEhRVvqjF0E6+ZSr5JdPnF1c5mE34Kv+98WRltcVtbfgA/ecRMNBaN9w
         1sLcJfE3sR9XEzm56iegZe5yLFWV8z68w+VRY6PQQeZZ7uXDYT1qaymmiNHEzDFJqz72
         NNc6j7ELd6nXtCq5Xoxfva4/RmJ6ZRaPYY1w1A6gFAcMeFyASPxULMOq1SxtRISNUozg
         YD/D12deNjRCkAkg1Wq+kYCLCc1RdM9h+5qgEo6fLLKZ9s8zdzmB8PAAuqyg+Tac6AnC
         KS6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vFDYWWex6iRLOgdk1JIotXQ89HmdObyXOaIPkDF429E=;
        b=dAlzKPzrC4cTNOtXDka3tHz8nTaG4IAxRGeRTickYxGOyGwfM68bTJqhn6oOh+zKwJ
         aCDyTbsph3inFoNF8LKsiKcHwU6YTchwoQcMfPdwLR0j6QgIxT7jQdrwGkyBm3HSlvF3
         EQaeIWhwa9rDyb0vuumYy6GlWKOWtv61bsUZ2LhoPpHCASt/e9eKtPpjLi2pn2fI7f3C
         ReBJvOMKs/bm5OcOkIXwh5apvo4xtOPFDpUeJ3TcTPGSDAuxfWx0hnnvFvOgbbkDHtqA
         KyT/L3wgl2fJEYMjxD1Qn9peikIpdN4feWprKxTGOeUKXMlEvQsVK1N12QeWB4eF+9xN
         ppFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="PO0SsL/c";
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id z78si1084428ilj.5.2019.11.18.08.20.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Nov 2019 08:20:11 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id n14so15795704oie.13
        for <kasan-dev@googlegroups.com>; Mon, 18 Nov 2019 08:20:11 -0800 (PST)
X-Received: by 2002:aca:ccd1:: with SMTP id c200mr21380309oig.157.1574094010691;
 Mon, 18 Nov 2019 08:20:10 -0800 (PST)
MIME-Version: 1.0
References: <20191115191728.87338-1-jannh@google.com> <20191115191728.87338-2-jannh@google.com>
 <20191118142144.GC6363@zn.tnic> <CACT4Y+bCOr=du1QEg8TtiZ-X6U+8ZPR4N07rJOeSCsd5h+zO3w@mail.gmail.com>
In-Reply-To: <CACT4Y+bCOr=du1QEg8TtiZ-X6U+8ZPR4N07rJOeSCsd5h+zO3w@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 18 Nov 2019 17:19:44 +0100
Message-ID: <CAG48ez1AWW7FkvU31ahy=0ZiaAreSMz=FFA0u8-XkXT9hNdWKA@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] x86/traps: Print non-canonical address on #GP
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Borislav Petkov <bp@alien8.de>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Sean Christopherson <sean.j.christopherson@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="PO0SsL/c";       spf=pass
 (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::243 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Mon, Nov 18, 2019 at 5:03 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> On Mon, Nov 18, 2019 at 3:21 PM Borislav Petkov <bp@alien8.de> wrote:
> >
> > On Fri, Nov 15, 2019 at 08:17:27PM +0100, Jann Horn wrote:
> > >  dotraplinkage void
> > >  do_general_protection(struct pt_regs *regs, long error_code)
> > >  {
> > > @@ -547,8 +581,15 @@ do_general_protection(struct pt_regs *regs, long error_code)
> > >                       return;
> > >
> > >               if (notify_die(DIE_GPF, desc, regs, error_code,
> > > -                            X86_TRAP_GP, SIGSEGV) != NOTIFY_STOP)
> > > -                     die(desc, regs, error_code);
> > > +                            X86_TRAP_GP, SIGSEGV) == NOTIFY_STOP)
> > > +                     return;
> > > +
> > > +             if (error_code)
> > > +                     pr_alert("GPF is segment-related (see error code)\n");
> > > +             else
> > > +                     print_kernel_gp_address(regs);
> > > +
> > > +             die(desc, regs, error_code);
> >
> > Right, this way, those messages appear before the main "general
> > protection ..." message:
> >
> > [    2.434372] traps: probably dereferencing non-canonical address 0xdfff000000000001
> > [    2.442492] general protection fault: 0000 [#1] PREEMPT SMP
> >
> > Can we glue/merge them together? Or is this going to confuse tools too much:
> >
> > [    2.542218] general protection fault while derefing a non-canonical address 0xdfff000000000001: 0000 [#1] PREEMPT SMP
> >
> > (and that sentence could be shorter too:
> >
> >         "general protection fault for non-canonical address 0xdfff000000000001"
> >
> > looks ok to me too.)
>
> This exact form will confuse syzkaller crash parsing for Linux kernel:
> https://github.com/google/syzkaller/blob/1daed50ac33511e1a107228a9c3b80e5c4aebb5c/pkg/report/linux.go#L1347
> It expects a "general protection fault:" line for these crashes.
>
> A graceful way to update kernel crash messages would be to add more
> tests with the new format here:
> https://github.com/google/syzkaller/tree/1daed50ac33511e1a107228a9c3b80e5c4aebb5c/pkg/report/testdata/linux/report
> Update parsing code. Roll out new version. Update all other testing
> systems that detect and parse kernel crashes. Then commit kernel
> changes.

So for syzkaller, it'd be fine as long as we keep the colon there?
Something like:

general protection fault: derefing non-canonical address
0xdfff000000000001: 0000 [#1] PREEMPT SMP

And it looks like the 0day test bot doesn't have any specific pattern
for #GP, it seems to just look for the panic triggered by
panic-on-oops as far as I can tell (oops=panic in lkp-exec/qemu, no
"general protection fault" in etc/dmesg-kill-pattern).

> An unfortunate consequence of offloading testing to third-party systems...

And of not having a standard way to signal "this line starts something
that should be reported as a bug"? Maybe as a longer-term idea, it'd
help to have some sort of extra prefix byte that the kernel can print
to say "here comes a bug report, first line should be the subject", or
something like that, similar to how we have loglevels...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez1AWW7FkvU31ahy%3D0ZiaAreSMz%3DFFA0u8-XkXT9hNdWKA%40mail.gmail.com.
