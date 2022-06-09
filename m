Return-Path: <kasan-dev+bncBCMIZB7QWENRBVOMQ6KQMGQEUQVUJOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 16EC6544BA6
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 14:23:50 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id o18-20020a5d4a92000000b00213b4eebc25sf4873231wrq.21
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 05:23:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654777429; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q0OPbiEP7+EHCCjX7mxhvsg87L7Nv3z9vNGCLYcvzvsJ0gf1lUb2dNkGxyRlVeyYUn
         /zAgrsmS7bdiSoxqpN6nnh2PK5croDF8IQ7uikXzXFCvgRnyLTNOKk34/6zr3cE8Qx3q
         9AMXrmtNnP11NJ8lLCdiKeOtDNwDCHix1Io13nHzwM8IgUWaYrENZ685JP0OrrrpVcO4
         53PWgRBcx9FGaj8oHu6j8tcWnhduYhy+FUFdE9AW7PCC7+5+GMlpqoEF462JMdqTEGxT
         IyI9EJWIieKxV3JbzaTgsVIIcTidZXh0oY2CWUTJ5FCP51yURFylyPM+gGztbOD3aGZ3
         Mxow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=EsbO70klxh70mWjCyY2X+vIPo//eKhp30aUaV6qExM4=;
        b=ylEAFheTyOn58rtGt4kL/747doLT/Lxmdy3TSgQLzNZ/z/rGpg8szAJFWWvhe5NSwt
         0E2vEER52Pr5W1xJ1K6rygKHkBW3wGsdhZtwGErt+9mZgg2xJv98cJF/MdiWG7E+C+as
         T33Sg+2+m9ioJnrygpiRrIXltD83HF+C+RchR37+9+BmRpJjmr3Up1bsvpkuR8bYgyV1
         gWtnzLuy/UJxiWr+qUIoN13m/wtTJzquyAVe1tDk51E7kWstxEUBlYn3+QEGdTXdQgjM
         idpdEZAvA1+pZLx8jGgVOEYPZsyKSNrZoggtkAgVvUkyT8Kv1H4dIJUR77Cr307M0oy7
         UbBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PFIHGY61;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EsbO70klxh70mWjCyY2X+vIPo//eKhp30aUaV6qExM4=;
        b=nDtVQhIBRCTEIvaSgkBRqPP6kZP4595Kqa3P39gWAplDQrIyMx5GyBliSNp3OFRgUE
         k06rZ5DQCGBEecALNdyPDJ0wPKxNw6fowHszKA8wpZFj3PXkmstLZgW7glWBH6Afs1Qy
         I7Z9pP2EWn2ZbhCe4c6UlGwE/0nW3yfBqZFHgyyWK0SjZ9k51NNVxG/iS9t3SnDt1vOp
         +f1KurSUoa+b+Qx2hrdreFGzOAQyVHPpPaMiuDusS0LOTRDM4aE56SSJ89/BKX3IOQoH
         fcaWVnXOygzeuo67u5/uBRLUsgzRhQTr1dA4a3Y3X2Icy2A8ZEtx5RX9qOPJ3/DDpwM3
         digg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EsbO70klxh70mWjCyY2X+vIPo//eKhp30aUaV6qExM4=;
        b=YSDAGlxIZl2btFUscB40i3PYMavG++tqnp2IRecVp8xGSeehYyuk3DH6Hwg0EZtqOn
         5KGH4Yz8ERrkyPj9JUArrlpywWf1Ck6mAQjrDu6y67i949pIA+VV4py/7ScABYyJwUV5
         74AKKDh86oK3UYgOVLjomhxUKLXofxkT7aXFEjtV+KDLH64XVTf6hJlMOwj2/K9DmSJU
         /wCdoS4GH0Vj0Hng6TuWITsYDGmYyCjBYGfv2kgWYUy60waULxBOJ43IIqU0EZNnomw1
         gxY0oBfYlmLGqMD9sqGi9Bw+LVkTY0IfIz6ar5uJxyM915W4SMVD413nV5Uz2g1pE1s/
         c6Vw==
X-Gm-Message-State: AOAM531u0rXmo21FOUzyIPRf5HRz177FRiI328oSELwC23mqINndYdHf
	PVVNpVVJ4YYOZ4aKSBVVEUo=
X-Google-Smtp-Source: ABdhPJxH2CPrWKPQJdJm03kSmf5lKJWSOc6GC7NKsiUF32hP0mpb6YPVubz4BLrbTvPd7ij3jQ/FDg==
X-Received: by 2002:a05:600c:3495:b0:39c:6a72:f286 with SMTP id a21-20020a05600c349500b0039c6a72f286mr3162679wmq.116.1654777429232;
        Thu, 09 Jun 2022 05:23:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6dab:0:b0:212:d9db:a98 with SMTP id u11-20020a5d6dab000000b00212d9db0a98ls1226050wrs.3.gmail;
 Thu, 09 Jun 2022 05:23:48 -0700 (PDT)
X-Received: by 2002:a5d:6510:0:b0:216:f04d:3c50 with SMTP id x16-20020a5d6510000000b00216f04d3c50mr25429014wru.628.1654777428352;
        Thu, 09 Jun 2022 05:23:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654777428; cv=none;
        d=google.com; s=arc-20160816;
        b=brtm7ciBUHYw9yO4b1bIWPJWE/PVmZk1pg49w/60IZHHwdLPfUhJFeenxdQT67Ez5C
         TgWdEwUwSN/hvKi1WZZr6C6s1a7JeYIgqWFn3ve7xnhSnf5K/8dE/GiRpy8dlmnKHlmf
         MPKE6U/5Ohq4QQLqZdWEWpDft3jOnKy9rJy/d6cuAgcGc4XKfLLYANklPGPM5oWldxOL
         6KGFxm2BeMNcPGvv86Y50ACqajxriqBb9ixbu8jG2HmVJG7BUj+tq7nSr2x+2k9S8Vfp
         LekmcM3AdLZNoQlbQBRfSEOwVCNDH1gYe12yMzYdjCkPmeLsQepQNlUCfL3yPzFUQgO+
         xLpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=llootBNvnKzlHSo7HBVwmmGvWmrZUKeALsskuPp9oY4=;
        b=rNAHawEEViCUy5BhjSqkJLzoJd6UwoIniK49jiq6LFp1WxFgJ8EPmowf7W3ByikoJ1
         kqDKQTCW668J7HxI/VnXiO5k0yLPqFJRynrSLrIQiV4uxDcWkxy8ooFGGegmw36/pK3D
         YO1yYffO63EEAPntpoyg79/MaQYP/rPmXpLyu05T5taxx7GfiGjoHEZYh4gvDRTUoOxU
         C09fTvhkovZygkzFOe02on5GVqNBq+B+Ht6NbQkftmenAn4HkrIfD7VmwUSgfwIErrpC
         C99FF6CA8eXmzwVB8peMbOOWT2f8s06cuWl+ql1r1OKvGV0zW72N7Zpbis2ivZOOwBlh
         OYbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PFIHGY61;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x132.google.com (mail-lf1-x132.google.com. [2a00:1450:4864:20::132])
        by gmr-mx.google.com with ESMTPS id j6-20020a5d4526000000b0020c9eedfe67si863194wra.3.2022.06.09.05.23.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 05:23:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::132 as permitted sender) client-ip=2a00:1450:4864:20::132;
Received: by mail-lf1-x132.google.com with SMTP id u23so37741060lfc.1
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 05:23:48 -0700 (PDT)
X-Received: by 2002:a05:6512:1085:b0:479:478b:d2cc with SMTP id
 j5-20020a056512108500b00479478bd2ccmr12747169lfg.540.1654777427515; Thu, 09
 Jun 2022 05:23:47 -0700 (PDT)
MIME-Version: 1.0
References: <20220609113046.780504-1-elver@google.com> <20220609113046.780504-5-elver@google.com>
 <CACT4Y+YHp1mxxGNuGke42qcph0ibZb+6Ri_7fNJ+jg11NL-z8g@mail.gmail.com> <CANpmjNMA=UKzpURckHh_Ss14oRoTQ7nZ4yqcb=nV1kBtEcEkdw@mail.gmail.com>
In-Reply-To: <CANpmjNMA=UKzpURckHh_Ss14oRoTQ7nZ4yqcb=nV1kBtEcEkdw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jun 2022 14:23:36 +0200
Message-ID: <CACT4Y+ayhGH253WA_zXYJjfOK=YxGLDZLzkyyqLHW+EZzJYpEg@mail.gmail.com>
Subject: Re: [PATCH 4/8] perf/hw_breakpoint: Make hw_breakpoint_weight() inlinable
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, x86@kernel.org, 
	linux-sh@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=PFIHGY61;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::132
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

On Thu, 9 Jun 2022 at 14:08, Marco Elver <elver@google.com> wrote:
> > > Due to being a __weak function, hw_breakpoint_weight() will cause the
> > > compiler to always emit a call to it. This generates unnecessarily bad
> > > code (register spills etc.) for no good reason; in fact it appears in
> > > profiles of `perf bench -r 100 breakpoint thread -b 4 -p 128 -t 512`:
> > >
> > >     ...
> > >     0.70%  [kernel]       [k] hw_breakpoint_weight
> > >     ...
> > >
> > > While a small percentage, no architecture defines its own
> > > hw_breakpoint_weight() nor are there users outside hw_breakpoint.c,
> > > which makes the fact it is currently __weak a poor choice.
> > >
> > > Change hw_breakpoint_weight()'s definition to follow a similar protocol
> > > to hw_breakpoint_slots(), such that if <asm/hw_breakpoint.h> defines
> > > hw_breakpoint_weight(), we'll use it instead.
> > >
> > > The result is that it is inlined and no longer shows up in profiles.
> > >
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > ---
> > >  include/linux/hw_breakpoint.h | 1 -
> > >  kernel/events/hw_breakpoint.c | 4 +++-
> > >  2 files changed, 3 insertions(+), 2 deletions(-)
> > >
> > > diff --git a/include/linux/hw_breakpoint.h b/include/linux/hw_breakpoint.h
> > > index 78dd7035d1e5..9fa3547acd87 100644
> > > --- a/include/linux/hw_breakpoint.h
> > > +++ b/include/linux/hw_breakpoint.h
> > > @@ -79,7 +79,6 @@ extern int dbg_reserve_bp_slot(struct perf_event *bp);
> > >  extern int dbg_release_bp_slot(struct perf_event *bp);
> > >  extern int reserve_bp_slot(struct perf_event *bp);
> > >  extern void release_bp_slot(struct perf_event *bp);
> > > -int hw_breakpoint_weight(struct perf_event *bp);
> > >  int arch_reserve_bp_slot(struct perf_event *bp);
> > >  void arch_release_bp_slot(struct perf_event *bp);
> > >  void arch_unregister_hw_breakpoint(struct perf_event *bp);
> > > diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> > > index 8e939723f27d..5f40c8dfa042 100644
> > > --- a/kernel/events/hw_breakpoint.c
> > > +++ b/kernel/events/hw_breakpoint.c
> > > @@ -125,10 +125,12 @@ static __init int init_breakpoint_slots(void)
> > >  }
> > >  #endif
> > >
> > > -__weak int hw_breakpoint_weight(struct perf_event *bp)
> >
> > Humm... this was added in 2010 and never actually used to return
> > anything other than 1 since then (?). Looks like over-design. Maybe we
> > drop "#ifndef" and add a comment instead?
>
> Then there's little reason for the function either and we can just
> directly increment/decrement 1 everywhere. If we drop the ability for
> an arch to override, I feel that'd be cleaner.
>
> Either way, codegen won't change though.
>
> Preferences?

I don't have strong preferences either way.
Can also be:
#define HW_BREAKPOINT_WEIGHT 1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BayhGH253WA_zXYJjfOK%3DYxGLDZLzkyyqLHW%2BEZzJYpEg%40mail.gmail.com.
