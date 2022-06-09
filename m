Return-Path: <kasan-dev+bncBC7OBJGL2MHBBF72Q6KQMGQERWKENYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 22CB3544E4B
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 16:00:57 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id z67-20020a254c46000000b0065cd3d2e67esf20261782yba.7
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 07:00:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654783256; cv=pass;
        d=google.com; s=arc-20160816;
        b=E6U3+Iub/YuMBBgbhnetYX1mXwZhA4hArvwVkLG3MvmKe6n/3GLucPC+Rv3wm+iYLR
         +UCAv2KJOp9oKtGcfXYT73jBLYBqoeff+rLlwxRxxRvLftNFoMjXi5bkHd9Ilu4Afbr6
         b5qt/nuHwJ5Y1jLneM3nfru+oxIttn442XBVBdphKJzYmYrORmpfliF+wuGS7pf2RT3B
         hzms8QZ3d3tOLYaZWotMUt/wGn/A6pvwSdhEEHvL9MXnAGpBROs+GN8ZjR+O7B+LdbuI
         4Zi5G8IWFPP9CvTPzULgBMpSr9roxn6z1GDrjQrGUiaRB3vGsNK/MvnLGXb5N5+BOI71
         z4FQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tT5259OPzMV8DfWOTJCBhRPoR8IbDKLVMnYdLNTxMH8=;
        b=gKI53Srvd6BavGpbibf93xE4JcAeyDrYxU32/IHEORE2Q571AuNeViQYyLyz/hYahG
         K9HQ7KYOTRErYa5Sntiomo3dfZA/DnmaIkBObz3sONm/b9hI4q2mGWrAWBIenuis4nAk
         lskx5U4Kqglwl4vBh3GI6OGqmOEm3KV6EfEjJEFZ3LIDAjx3VAcCn7QdvJ12sFMFD/QB
         mFPmcpGxFiJvDsye3D0ex1iJliLsD2IFl/n46wmvsLjWbBxnLHcbF0KqV8ogge6trgyD
         okHx+PBm9vfIeUYsujSm6nt+Ja6iRC0fpBpp8qboeO2GuM4vnhJwRWX/mfiPPB+UwOlN
         xdRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fGOxnn0A;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tT5259OPzMV8DfWOTJCBhRPoR8IbDKLVMnYdLNTxMH8=;
        b=DL2R6nXogdce3/eqXGHAngAQKEq3RXOytDvhyLeBddFckBR2YtA0vflIe6PAVLn71T
         gcIW7X420EFCW95TJ9zbHUw3NBQQkOP+55UTNKpFGgW83I+Qf4z3mvcxuz6S3Ak9Gq8S
         2RUO2PZVuKIW3H0uuHuLYA/85kRzN8QMcrACv96GOx4BKSoPv4nDnRfxlQImQhSlDDka
         Vll809E34BiEmKzy51M5mrOlvi2WxHZS9/TYapUWvMxpe4Jsr6BOeP4D2/aE/0tjRnL1
         1JlvXVQGGteOQ1L/Ctmw3rAsDAg3jv1Z5iE9cDtediuUjY0ygi4wssURTDlRelmNBb2e
         ZVJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tT5259OPzMV8DfWOTJCBhRPoR8IbDKLVMnYdLNTxMH8=;
        b=YZ6JOgMfYiv+SEVusuwxAZwBoLxRj9eP91lFLqVVhawDHDHfEj7zN6S/zc+GX76uYO
         /yq05spxWVqi2dJBQIEvUhw1vVLjTt5T+L3PPQTdo3AmeMK+9EfDgBrJV6jYQDC4JsN6
         Tp6bdS094BZoWbVjf4gvEHjgug5e7TMuyfkFYqKJKLwx18e/CbZDOqK4vjWfq/AJ3q+g
         hO2WBcesayia98o3dfBUte8C1XnCHg84P1IrOBSHO63i+8AkpmLvgTamhetnudp5JPzM
         p0CWzShH2GNEglJIrZ3sgLPexGFiHc/G4KoSKcMhXr2tDOpWtRgGWB/71yBK8fmnpM5A
         hyyA==
X-Gm-Message-State: AOAM533ST/pc29SF4ZEMbQWxIkuAbTpZCjjrvubSmYYUFmzw20nQEEYl
	HQ5Vz0PC9ohpM5dIKCBxSOQ=
X-Google-Smtp-Source: ABdhPJx3TpfHXFYG/1LcHjZpuxU/EhIkFLEoGJf6SumXok8QEsqZtvmBu+MnN5WgY1j4qD0gR4HXYw==
X-Received: by 2002:a25:6b12:0:b0:65c:d2b1:edb3 with SMTP id g18-20020a256b12000000b0065cd2b1edb3mr38241657ybc.97.1654783255735;
        Thu, 09 Jun 2022 07:00:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:73d6:0:b0:65d:5fb3:5381 with SMTP id o205-20020a2573d6000000b0065d5fb35381ls3631335ybc.7.gmail;
 Thu, 09 Jun 2022 07:00:55 -0700 (PDT)
X-Received: by 2002:a05:6902:120d:b0:660:d02b:a31e with SMTP id s13-20020a056902120d00b00660d02ba31emr32732796ybu.275.1654783255137;
        Thu, 09 Jun 2022 07:00:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654783255; cv=none;
        d=google.com; s=arc-20160816;
        b=gpDssQqdWrav1N1H1HIMtJQj4PVbBePkE9mS0Hr9B3Et5O5yU2VhIBOxd5Aml/Sj38
         NnDRA6JYUhLtpNE7pF/l38a78iOJcZ1zakVwpab7kJgUU80B7n3XEPly+gTQZkicOme/
         rkpivx/wAbu0efsg2Q1BISvFMcRcMUoO7Bn2/QaFQJvwrJ/wfOAk2OM+e6t+qYBOozK9
         dkJarAvaICWRyLbA+RD3R2n+Xl90u8VOaEbTyQ5XrMXDWHbGyuPCgelqWCPh3G1Vd1Ud
         bcxcK7c9f5aSZ0bNdQ6VTVc6gz0zhQ8O8+X/ENKc3ZaAkZ5/SVFgQhrjqYj/LqWMVrnA
         vaLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jqhwYhya53Ub6ysqItH4y8unqJO0QhApIrC1/649j54=;
        b=ivqMA9B4a+4wJHuZyExcOGTnPjkHKImHskJlSISGahiu6pnzk4Qu53+L/8iJ4QHz7a
         aZzrGXctCs6NkCvCtaMncWubP33vjzqPEw4xbdgLnC+i76iayx048uLb9SoeWO0OH3vV
         2SYBAJQLY6kb/jlFZlrBr9VHaa31dQPaUw4+sGI/rQdKJKYIdmwfAKN5RMiPP2tUAQhz
         YwOf/3MmbKD9i2uyPTVmQQLCZ93X4OUl0s/hxQ50YRZCb9LItetq6SDRtY584j3dEUz5
         L+T2j8VX/KFJ9NKSNv97cWedQSCHUBjqrTS2uK5i1wE9Xb9DQJVG8TeHst69ssctAS3M
         4Cmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fGOxnn0A;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2b.google.com (mail-yb1-xb2b.google.com. [2607:f8b0:4864:20::b2b])
        by gmr-mx.google.com with ESMTPS id j203-20020a8155d4000000b0030c2e0694absi1983705ywb.2.2022.06.09.07.00.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 07:00:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2b as permitted sender) client-ip=2607:f8b0:4864:20::b2b;
Received: by mail-yb1-xb2b.google.com with SMTP id i39so13892920ybj.9
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 07:00:55 -0700 (PDT)
X-Received: by 2002:a25:780b:0:b0:664:3e22:3368 with SMTP id
 t11-20020a25780b000000b006643e223368mr2020008ybc.625.1654783254347; Thu, 09
 Jun 2022 07:00:54 -0700 (PDT)
MIME-Version: 1.0
References: <20220609113046.780504-1-elver@google.com> <20220609113046.780504-6-elver@google.com>
 <CACT4Y+Zd0Zd_66DZ-f2HG4tR6ZdraFe9b4iEBJmG9p72+7RMWQ@mail.gmail.com> <CACT4Y+appPi5YAdKFB-2caO6xkg89FmV1_4532u7Jx_5CAX9xw@mail.gmail.com>
In-Reply-To: <CACT4Y+appPi5YAdKFB-2caO6xkg89FmV1_4532u7Jx_5CAX9xw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jun 2022 16:00:16 +0200
Message-ID: <CANpmjNP7pUYY7T1pCOVCJ_WaomdeuQzcLin46VVtyEmT4pQ4iA@mail.gmail.com>
Subject: Re: [PATCH 5/8] perf/hw_breakpoint: Remove useless code related to
 flexible breakpoints
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, x86@kernel.org, 
	linux-sh@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=fGOxnn0A;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2b as
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

On Thu, 9 Jun 2022 at 15:41, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, 9 Jun 2022 at 14:04, Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Thu, 9 Jun 2022 at 13:31, Marco Elver <elver@google.com> wrote:
> > >
> > > Flexible breakpoints have never been implemented, with
> > > bp_cpuinfo::flexible always being 0. Unfortunately, they still occupy 4
> > > bytes in each bp_cpuinfo and bp_busy_slots, as well as computing the max
> > > flexible count in fetch_bp_busy_slots().
> > >
> > > This again causes suboptimal code generation, when we always know that
> > > `!!slots.flexible` will be 0.
> > >
> > > Just get rid of the flexible "placeholder" and remove all real code
> > > related to it. Make a note in the comment related to the constraints
> > > algorithm but don't remove them from the algorithm, so that if in future
> > > flexible breakpoints need supporting, it should be trivial to revive
> > > them (along with reverting this change).
> > >
> > > Signed-off-by: Marco Elver <elver@google.com>
> >
> > Was added in 2009.
> >
> > Acked-by: Dmitry Vyukov <dvyukov@google.com>
> >
> > > ---
> > >  kernel/events/hw_breakpoint.c | 12 +++---------
> > >  1 file changed, 3 insertions(+), 9 deletions(-)
> > >
> > > diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> > > index 5f40c8dfa042..afe0a6007e96 100644
> > > --- a/kernel/events/hw_breakpoint.c
> > > +++ b/kernel/events/hw_breakpoint.c
> > > @@ -46,8 +46,6 @@ struct bp_cpuinfo {
> > >  #else
> > >         unsigned int    *tsk_pinned;
> > >  #endif
> > > -       /* Number of non-pinned cpu/task breakpoints in a cpu */
> > > -       unsigned int    flexible; /* XXX: placeholder, see fetch_this_slot() */
> > >  };
> > >
> > >  static DEFINE_PER_CPU(struct bp_cpuinfo, bp_cpuinfo[TYPE_MAX]);
> > > @@ -71,7 +69,6 @@ static bool constraints_initialized __ro_after_init;
> > >  /* Gather the number of total pinned and un-pinned bp in a cpuset */
> > >  struct bp_busy_slots {
>
> Do we also want to remove this struct altogether? Now it becomes just
> an int counter.

Yes, that actually can simplify a bunch of things, including
fetch_bp_busy_slots() just returning an int and fetch_this_slot() can
be removed (it'll be even cleaner if we remove the overridable
weight).

I'll simplify unless I hear objections.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP7pUYY7T1pCOVCJ_WaomdeuQzcLin46VVtyEmT4pQ4iA%40mail.gmail.com.
