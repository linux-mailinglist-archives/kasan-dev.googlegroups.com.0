Return-Path: <kasan-dev+bncBDYJPJO25UGBBS7C7GAQMGQEN56Z2CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id A643B32A766
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Mar 2021 18:09:31 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id j15sf7590078lfe.2
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Mar 2021 09:09:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614704971; cv=pass;
        d=google.com; s=arc-20160816;
        b=D9+6xde/R793Il95ddcqhFDne7cI0iYF2p+G5wMFZnLffRtdF5Q0SUpc/GFwDmPJVm
         rtVcuj4qq70jBZkXFd4thgj34s/7xbOTJE1f9OXlBThbCkaoRRCijebJsysmLZRO28JJ
         cwtBqq0LTSDkxDzN8PqYW2zHJVSAQ78ovKvdsJBpie45rB6NQZr1are4PENnJwlG9pW1
         sr8soihUBfyuWx/a6D/1M2Ir6Ugol9h44IyOknKmVC79ZBtqVWAPcwFXx8+VFERPW7sC
         CXhrxg2GO8e4YXnhKHPX/3pwbjoJY0tU6d/MIkxgybC+mpWVn9Y5cheuXy8tziPvDNF7
         ttDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1LJasThBDCWYABAI51F91GtBIaITU4JhzMMwjA+BFgg=;
        b=iJjMxrZDInksfgaQEriyWXlAENqnIOlnhl6M6Kb+y5wbI2HSOJIKvpOysWLG3x5BRT
         oH03DoVO8HHqDkMWbcL7cjZ8rd1m7F0uqvBEuU54pnY7gbSrWbDpC4m6ii8oH6DoQSyD
         PgWh/xNaGkzNDoWLIFJfERzPG3ryQncDIddngNdyH3r9mBYk+IXceDi/yKlHzxDQIUJR
         NExA58r+2i/o/TA6OU9lFW9D9WWbUgCvqTRnRDyHIIIM4keNv8EMdY1oe+nsso0RpIR6
         ZRUPHGj4A+9Ag2EXBAQdjvnV+EPz8GfCI9/zPJgtAPbsoBcckYRa6BnLe4iUZRsP1w62
         vR/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qC+HOvCE;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1LJasThBDCWYABAI51F91GtBIaITU4JhzMMwjA+BFgg=;
        b=ZzOI7F6LX53a9LTWGKT97OMkkRnvsmaUPfBse9k+MZfaKJz9oYcSN4aj5glsk6r5+6
         L0pztoaAM6tCdzcpXqhMPYub/cL5CB0rUhJHsmTMERG4/dZAI9jUyxs12WSvWUXbczlJ
         npry4OG1j6bI1MCPF1UowulPZumccjRnT+Ehu0V+Z10qs7wNUYJIEr0Pzowes45+DIS4
         u/iYaIZBsKmhb2wCNNZcPFc9mnDUxkwCF8MZ0AOCj61dB2xD170VakAAwgCkAiKPqUx6
         jnB1rZensqZxR4M01swlMG7+GkGYMzr45axvxLP46I6kKKQvJk2Mcxg74kpNmeYe9NeR
         dH0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1LJasThBDCWYABAI51F91GtBIaITU4JhzMMwjA+BFgg=;
        b=ITPhXa02DirDFpwsOGzdHgoeIn8kKWYcrB5dOEqqLdgSzLvynKee915Xpc8ifYT3Y7
         36YWgxIFTJaDa3TEUQfp8GsgEd6XGH6Er7NAvFAuc8k7bk8IbfigyuUN1+lMoT0snhYj
         4Tz/W1u53eEgQv84uPpkAJwdpZru/PjcGzfsj9Wxki1H8Vf/+nUyTLd/lqEZqCekojMT
         7i++Lm8fYs9Mzf2bCjrqKoVlsQ99GDX7xBd5spw3EYghEzkBvVpuyS1G2W7/OpcbPOZr
         BkOfF1+yXe9cJlCMxrsAQE3aT0ZrWaYMDSmVcBitjKSCrnxN5tdCKW/efHx5x4Z2Vz2X
         t/9g==
X-Gm-Message-State: AOAM531+MmFw5AV4y2a1uzdEuOYHB++j90UwQhY7l4zrZZ9DcK4TiYFp
	ZGn28M2AIeSc0mwolHhkRZk=
X-Google-Smtp-Source: ABdhPJz2odl+pefsi+4/wCMhl32k8Ai/8vztw/R1V5Dt7uUO0RcE1uOdoSKxQ2Ra+/BnwAw27CA1/A==
X-Received: by 2002:a2e:8691:: with SMTP id l17mr12620783lji.297.1614704971249;
        Tue, 02 Mar 2021 09:09:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls8642658lfu.3.gmail; Tue,
 02 Mar 2021 09:09:30 -0800 (PST)
X-Received: by 2002:a05:6512:3194:: with SMTP id i20mr13053039lfe.283.1614704970203;
        Tue, 02 Mar 2021 09:09:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614704970; cv=none;
        d=google.com; s=arc-20160816;
        b=Qtg8v+uw8V6+tfJVCwn/dWiChxPBQ2f4hH/j87hV6D7HqXxZkPUsjnpZj9zVXyw46I
         RzaXq2Td+K0om0b9XZCKrS5qmrZ8NHlKF1Ru9BRebNUZr6rM51XM8TDDXalyrXiCklzw
         EfPXdIqh//OKd0m5YxBUpL2EuSH2S0Hj2dyPI2UEGrZWOJQtWNUn+ZXwb618uoBZTyIV
         pr4+219PC6urMy4Pi5G9QB7EKj/+xw0HOpitrGsLrIUmPBYbXOVQthPDWYazMNyxReMn
         05wd4o+gcc3aRnKetoDgItZNfMs9uH7xbYz2EurLWUvU3L65Fmu+rkR/VpfJL2VFxjdG
         xQzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SG/fE5y/im+K5HgJBlEJfGfjEwANKTXRxT3cd0RvybI=;
        b=X4La+j4KmN+ouaNgvQ73wucOJx2xXAet+sxgS3nkwXsx8ceSkEMdYzQbibzealibUm
         LJ5f+nIan1vPEswfDYz82NCOk4JugtEBraReYwDGa07U1KtwzHsQ3tw9ZL8mqH2J4Dyj
         RJsoTDnCpGanEHPOXhAB0eeVFA8GB3cn/XFiaZrx+ltrCsHoyq8KnIqlKJJCGTbh8p7B
         nfeLOh9TS6i4RtraMsrlQadmIF23hyVA1r5/a5U8EIDq8KLJ0yvAMOqFg9px5sh60o2h
         beC+79vkm16cxXlZdjP3uRx6vpapho5iMvEbGTc8dwsKYmFCqlBGnXFGBeIasPzor+hh
         jenw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qC+HOvCE;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12a.google.com (mail-lf1-x12a.google.com. [2a00:1450:4864:20::12a])
        by gmr-mx.google.com with ESMTPS id c6si1103321ljk.2.2021.03.02.09.09.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Mar 2021 09:09:30 -0800 (PST)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::12a as permitted sender) client-ip=2a00:1450:4864:20::12a;
Received: by mail-lf1-x12a.google.com with SMTP id e7so32470909lft.2
        for <kasan-dev@googlegroups.com>; Tue, 02 Mar 2021 09:09:30 -0800 (PST)
X-Received: by 2002:ac2:4217:: with SMTP id y23mr12077143lfh.368.1614704969766;
 Tue, 02 Mar 2021 09:09:29 -0800 (PST)
MIME-Version: 1.0
References: <000801d656bb$64aada40$2e008ec0$@codeaurora.org>
 <CANpmjNMEtocM7f1UG6OFTmAudcFJaa22WTc7aM=YGYn6SMY6HQ@mail.gmail.com>
 <20200710135747.GA29727@C02TD0UTHF1T.local> <CANpmjNNPL65y23Qz3pHHqqdQrkK6CqTDSsD+zO_3C0P0xjYXYw@mail.gmail.com>
 <20200710175300.GA31697@C02TD0UTHF1T.local> <20200727175854.GC68855@C02TD0UTHF1T.local>
 <CANpmjNOtVskyAh2Bi=iCBXJW6GOQWxXpGmMj9T8Q7qGB7Fm_Ag@mail.gmail.com>
 <000601d6909d$85b40100$911c0300$@codeaurora.org> <20200923114739.GA74273@C02TD0UTHF1T.local>
 <CANpmjNNk8MHXNsHdyWqcO1VxREv+LP0sxid9LZOy+2Pk8i9h+w@mail.gmail.com> <20210302122653.GC1589@C02TD0UTHF1T.local>
In-Reply-To: <20210302122653.GC1589@C02TD0UTHF1T.local>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Mar 2021 09:09:18 -0800
Message-ID: <CAKwvOdnSz0H515TsF7ZMOtOiHO_G2ygAeb1-y-yW-ma0FvYg8g@mail.gmail.com>
Subject: Re: KCSAN Support on ARM64 Kernel
To: Mark Rutland <mark.rutland@arm.com>
Cc: Marco Elver <elver@google.com>, sgrover@codeaurora.org, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Daniel Kiss <daniel.kiss@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qC+HOvCE;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::12a
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

On Tue, Mar 2, 2021 at 4:26 AM Mark Rutland <mark.rutland@arm.com> wrote:
>
> [Adding Nick and Daniel]
>
> On Mon, Mar 01, 2021 at 02:09:43PM +0100, Marco Elver wrote:
> > It's 2021, and I'd like to check if we have all the pieces in place
> > for KCSAN support on arm64. While it might not be terribly urgent
> > right now, I think we have all the blockers resolved.
> >
> > On Wed, 23 Sept 2020 at 13:47, Mark Rutland <mark.rutland@arm.com> wrote:
> > [...]
> > > The main issues are:
> > >
> > > * Current builds of clang miscompile generated functions when BTI is
> > >   enabled, leading to build-time warnings (and potentially runtime
> > >   issues). I was hoping this was going to be fixed soon (and was
> > >   originally going to wait for the clang 11 release), but this seems to
> > >   be a larger structural issue with LLVM that we will have to workaround
> > >   for the timebeing.
> > >
> > >   This needs some Makefile/Kconfig work to forbid the combination of BTI
> > >   with any feature relying on compiler-generated functions, until clang
> > >   handles this correctly.
> >
> > I think https://reviews.llvm.org/D85649 fixed the BTI issue with
> > Clang. Or was there something else missing?
>
> I just had a go with the clang+llvm 11.0.1 binary release, and it looks
> like there's still some brokenness. Building v5.12-rc1 with defconfig +
> CONFIG_KCSAN I get a stream of warnings of the form:
>
> | warning: some functions compiled with BTI and some compiled without BTI
> | warning: not setting BTI in feature flags
>
> I took a look at arch/arm64/kernel/setup.o with objdump, and while
> almost all functions begin with a PACIASP (which can act like a BTI),
> there's a generated constructor function with neither a BTI nor a
> PACIASP:
>
> | 000000000000010c <tsan.module_ctor>:
> |  10c:   14000000        b       0 <__tsan_init>
>
> ... IIUC this is a case that D85649 intended to fix, but missed? I
> assume that D85649 is part of 11.0.1?

$ git branch -a --contains a88c722e6 | grep release
  remotes/origin/release/12.x
Looks like it landed in clang-12 (branched, but not released yet).

>
> The resulting kernel does link, but won't boot (due to the Linux
> structural issues I mentioned previously).
>
> Thanks,
> Mark.



-- 
Thanks,
~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKwvOdnSz0H515TsF7ZMOtOiHO_G2ygAeb1-y-yW-ma0FvYg8g%40mail.gmail.com.
