Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGFP7CAQMGQEPW6J2RY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 54D5C329A97
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Mar 2021 11:46:49 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id m19sf10637144oiw.19
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Mar 2021 02:46:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614682008; cv=pass;
        d=google.com; s=arc-20160816;
        b=BmB+mOFjHF2p4pHiRYYMeTALb/p0oG0kGN17uGUR5miHyE7lHiaWIYkJzfWpM0+YTD
         4nUZq6XfEHSDWxi5ucskZMNPw0HutSQPgpcig7hWB8eswomn1NiwQilNY692HQUA7BSH
         xT5iH94kuYC4tAfRhEgtyCk9qxBF5p1Gz5LqqDr2Ef1aODl7oAv0z54RdwbWWl6kOTXJ
         WIkK1g2yz9o9FmmahGXHt4KX4/HL2z6vw51/te77O+NxlYywebDSiEno/mRG3p+bJb9t
         qEcszByXOcVGRkn/RMYh7wRd7/xL7hzjTliWQcPO512EFoHB67tU4RM2SjR/GYt1Gzi4
         /W4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bQQIxEUpa1vz8O4rrWq5Ud9xdseLT4/3LihMWcwVR9Q=;
        b=TPOgccIzuL5P3Ppcz6lf9tKXnW0MzOwmP+NCS6hfXzVGW90DnSDeyPy5b4bNyJ1X92
         akfgQKz9kAMgpL95lPImi+ns322wrArTEiTte4euLI866GO53H6slE8u/IOSPc8VJinB
         buCdH2P02ToWJiZAevk2PV+JCFh4lL4qqWb8szIcu9k+DzqlqjG8khedb9gSl0AL1c8J
         lPUKNj6iF65yP4MgDq9YFBmv0dRGc6th7i0yd6ZEek+po4VSdYNH18T3FKv5IErlYGDW
         jq8nZy2S4BaxdsDfTb2zBolYZ/4ivAYLZ2Ipa2iDAY/Wd1Brm8XHJAiRl076uTii7z8E
         SVzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="nwu/saec";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bQQIxEUpa1vz8O4rrWq5Ud9xdseLT4/3LihMWcwVR9Q=;
        b=CnuGjlrM3mA+MbO3E+vYaZtlWaqoFiWsDDH+8W7WCwobXBUtF7h2yikZRJI0D+m9Mu
         L3p9CnPtwryEZWcxnwsSp1ilEB7sfBPcpkT2/yrvzjBlJyFMuRx30kLcBv1YWPjoJYlh
         NQ5FJg+QRtv9RVXdpY20VIhwN9AnDeQxoeumZSiF2+67xbwqe1TxxZGYiifPpCD91p18
         Eq0xlcJCm0rpIWDmB9IytaV/1c8eP7xOxPnYRGlyXZ0sjdMbopN76ZLUlIAfSjprsSfQ
         l4bJMBiBhnoOmKepIT6Vm/bgMlemcpHurWsqFqKjUsXaiTWwDksElYaIsmIi8OwxbPk7
         pRdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bQQIxEUpa1vz8O4rrWq5Ud9xdseLT4/3LihMWcwVR9Q=;
        b=ky1ooWF+PREp4N1VsqvYCOHxMqhva90UjfCK6dQoA1RGH5yaBnmolPYyDuQdGrvbXV
         w/AGBpvH21K0FlRrU4Ig0Gmt27bKM1h9mlB1Uwe6usoBWJPuONDyFitJRzSh0yV26kgQ
         3bMhUBsqKdSxuzFvim26c29bRUXsW6dgjVfJQF5RsKjq1ScnEdlC9StdaS2Ui8+sJzq/
         hXU1grFF88mi9Kp4zRJKn5Ti1/GVIPwBQG4j6M0MrCA2RflT7utXxCUBlmEXLmoU+FDc
         BVfVYCQgTfbEJ9PmKPJ35BpE1ctufyD3RIqlMhoBRpa3wTjOJfsS0KYTkU5s8eFQXy4v
         OqLQ==
X-Gm-Message-State: AOAM531xTy3vMN5+EUJVn50v2KLVA5U1qnqqJocZKFcK99pUQ7+pyYxR
	YAe1uvwUMmFBFPw7E1ALA/g=
X-Google-Smtp-Source: ABdhPJzdC8smjA2DHIeGvHyiLiCeCNJlQFyYb6wypjD8BXdEA7xn7cLjg2qvKqdIpXJT79X9qGq3kQ==
X-Received: by 2002:a05:6808:114e:: with SMTP id u14mr2722850oiu.156.1614682008316;
        Tue, 02 Mar 2021 02:46:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1156:: with SMTP id u22ls5179905oiu.6.gmail; Tue,
 02 Mar 2021 02:46:48 -0800 (PST)
X-Received: by 2002:aca:d946:: with SMTP id q67mr2679068oig.104.1614682007959;
        Tue, 02 Mar 2021 02:46:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614682007; cv=none;
        d=google.com; s=arc-20160816;
        b=cF4KA36nC+Z1/hRinjEYdeETDFaP8zt5ARVqciKcAA8wWjP1EDDEEjtZte21QGeHkE
         WL7LiNC569yEN15SCZ4MF+v34oKKoKWVdbgFx7xMwssBd1ivRxvejZkiIi75B9hSpQlc
         kqTAPBs2nrQWTsIYv+SEmchUZ1oMHW7uQj1bQIKCHQjaoXao/WAzKzv9j6DsjARXHLHd
         8PwdB0bEd1tWxFDQvWy2HYsj8LZbfMcCfXk1bw/beu3Omkx2GNfjPGY9tfRYNEfC9fEI
         NnVx84Qzjb3SwWnMUMBcXxsChs45dIL0QazlJ/WQF0+0ckR6ydODvUMr2j+xzscJ33N4
         X5cA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tI1T3sG8WiBrhhz5S5iMt3gLDFMM0aI3nta0Y1X6tTc=;
        b=xHPhlmgL4y8FE0f2z/MTea0KeJSNEfeHquj7yO+HpNjJ6rIYDjSO3EZLrrWQosDLnK
         4qRH+ozTJZ0PtLBnr1Y/n/8NV5/SKhUstkVeVyG/vgGbLxO2SCUc2ytVE9x1Oxz4tBcu
         Y3MxYZphhE5s53jWDSzVeUOFvxjgBVJQOa5EbmU2za7QE9xTMMNT9Sr0Pwgu/BWwf3wZ
         +qoKelKOQEl5xmMhtLfv4OJK5fXQIs1bz/xLd7EeddYqW//QyeR79+73y8bitUrnWb6Z
         DDFyStJGMQHfS1Al/hu40zRX4YEycvv3pgGnipIlAQUT21IWdz+aOyi1lhgY18bcqpCm
         CmQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="nwu/saec";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x231.google.com (mail-oi1-x231.google.com. [2607:f8b0:4864:20::231])
        by gmr-mx.google.com with ESMTPS id v4si343250oiv.4.2021.03.02.02.46.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Mar 2021 02:46:47 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as permitted sender) client-ip=2607:f8b0:4864:20::231;
Received: by mail-oi1-x231.google.com with SMTP id x20so21448340oie.11
        for <kasan-dev@googlegroups.com>; Tue, 02 Mar 2021 02:46:47 -0800 (PST)
X-Received: by 2002:aca:5fd4:: with SMTP id t203mr2651357oib.121.1614682007451;
 Tue, 02 Mar 2021 02:46:47 -0800 (PST)
MIME-Version: 1.0
References: <000801d656bb$64aada40$2e008ec0$@codeaurora.org>
 <CANpmjNMEtocM7f1UG6OFTmAudcFJaa22WTc7aM=YGYn6SMY6HQ@mail.gmail.com>
 <20200710135747.GA29727@C02TD0UTHF1T.local> <CANpmjNNPL65y23Qz3pHHqqdQrkK6CqTDSsD+zO_3C0P0xjYXYw@mail.gmail.com>
 <20200710175300.GA31697@C02TD0UTHF1T.local> <20200727175854.GC68855@C02TD0UTHF1T.local>
 <CANpmjNOtVskyAh2Bi=iCBXJW6GOQWxXpGmMj9T8Q7qGB7Fm_Ag@mail.gmail.com>
 <000601d6909d$85b40100$911c0300$@codeaurora.org> <20200923114739.GA74273@C02TD0UTHF1T.local>
 <CANpmjNNk8MHXNsHdyWqcO1VxREv+LP0sxid9LZOy+2Pk8i9h+w@mail.gmail.com> <20210302102816.GA1589@C02TD0UTHF1T.local>
In-Reply-To: <20210302102816.GA1589@C02TD0UTHF1T.local>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Mar 2021 11:46:36 +0100
Message-ID: <CANpmjNN-cqXBhXYiQRqTOBv2in_zr3=KkTR7YASKUYqjorqQ-A@mail.gmail.com>
Subject: Re: KCSAN Support on ARM64 Kernel
To: Mark Rutland <mark.rutland@arm.com>
Cc: sgrover@codeaurora.org, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="nwu/saec";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, 2 Mar 2021 at 11:28, Mark Rutland <mark.rutland@arm.com> wrote:
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
> I *think* so, but I haven't had a chance to go test with a recent clang
> build. I see there's now as 11.1.0 build out on llvm.org, so I can try
> to give that a spin in a bit, if no-one else does.
>
> > > * KCSAN currently instruments some functions which are not safe to
> > >   instrument (e.g. code used during code patching, exception entry),
> > >   leading to crashes and hangs for common configurations (e.g. with LSE
> > >   atomics). This has also highlisted some existing issues in this area
> > >   (e.g. with other instrumentation).
> > >
> > >   I'm auditing and reworking code to address this, but I don't have a
> > >   good enough patch series yet. I intend to post that prework after rc1,
> > >   and hopefully the necessary bits are small enough that KCSAN can
> > >   follow in the same merge window.
>
> On this part, I know we still need to do a couple of things:
>
> * Deal with instrumentation of early boot code. We need to set the
>   per-cpu offset earlier, and might also need to mark more of this as
>   noinstr.
>
>   I'll go respin the per-cpu offset patch in a moment as that's trivial.
>
> * Prevent instrumentation of the patching/alternatives code, which I saw
>   blow up when instrumented. For KCSAN we can probably survive with a
>   simple refactoring and marking a few things as noinstr, but there's a
>   more general unsoundness problem here since the patching code calls
>   code whihc can be instrumented or patched (e.g. bitops, cache
>   maintenance, common ID register accessors), and making this watertight
>   will require some more invasive rework that I hadn't quite figured
>   out.

Ok, that sounds like it's a bit more complicated then.

> * I have a vague recollection that there was some problem with atomics,
>   and that in some cases we'd need to use arch_atomic() rather than
>   atomic(), but I can't remember whether that was to do with the
>   patching code or elsewhere.

I think this was inside noinstr functions, because ifdef ARCH_ATOMIC,
atomic ops are instrumented via atomic-instrumented.h.

> > [...]
> > > > -----Original Message-----
> > > > From: Marco Elver <elver@google.com>
> > [...]
> > > > Let's see which one comes first: BTI getting fixed with Clang; or mainlining GCC support [1] and having GCC 11 released.
> >
> > If Clang still has issues, KCSAN works with GCC 11, which will be
> > released this year.
> >
> > Mark, was there anything else blocking?
>
> I think it's just the bits above, but I haven't had the chance to look
> at this actively for a short while, so there might be more issues that
> have cropped up since I last looked.

Thanks for the summary above, we'll be patient as there's no rush. I
thought that the patches you had would hopefully "just work" with a
few minor additions, but it seems that was wishful thinking. :-)

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN-cqXBhXYiQRqTOBv2in_zr3%3DKkTR7YASKUYqjorqQ-A%40mail.gmail.com.
