Return-Path: <kasan-dev+bncBC7OBJGL2MHBBN4JWKFAMGQE6GKHREA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C329416036
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 15:44:25 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id bk33-20020a05620a1a2100b00432fff50d40sf18648263qkb.22
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 06:44:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632404664; cv=pass;
        d=google.com; s=arc-20160816;
        b=TRgbRSOpeaXZs98PQuG96C5OIrFq26JFI4h9EZGbZfMUrpNXmu8JS3NjxWXupyDNFG
         hpmLsEQe/mdCzU3ugbDUDK0zKwNfPIgNuQBv0os28PMK8+XnM3uvPHe5i1ddAtaNCjba
         a/ciQy3+M+KLUVDmBQEg16E0NwEzuTwLuveZIsvxRVw1/CY/bHbh4Kw7EssRQy30PSf8
         tMFBfRWIidul4+2NncGPy6jEDouTjfP/OH856wQoPonesKRWGIbwZy9ukc1uL+jdUkjA
         wI+3SZEhwenw+8K1Z4uVbjMOizyVudH1WOWh1NvK+h1rq4HxsLOyV6zPJ5yAZx0uf4Ss
         lamA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5E58KtWGzMT334elrz8QH/ff1Mr2Y+gzCpedhKKM1Bo=;
        b=sFKhTalx7Ly5KgQ7HHN3oCJjBAlxQf0UWzSiifo08/61vP+WW8ZEK9l1sC81Rj9LmB
         +KpV2zr44TWJFwjocVYfrmOKOrE6Y6+YxLpgVc7ZS21ZAzgjyFXtPVybjbXpljMefE7p
         /sP1cfVX0NPNe0fuwzlaAFfN2+QQc1+FYweHyYvTzt1joHJUTNONoQoDTLa88VAVrVTl
         aoANHiILdCovuRZ2pRbIwn/ptBem7oDXuiBupA99DMUN/EsBk2+dNjigKODBcu8A2xgs
         099EczSJxaOLXGQvhQ/pX72wR7rRdm6YXr5fot8Nj4Fm793hHxGq2KQyvXFB6sD9ysO2
         jBgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="LWu70/eB";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5E58KtWGzMT334elrz8QH/ff1Mr2Y+gzCpedhKKM1Bo=;
        b=ciRbjM3WcPxvqjHB7ANMNJFAZpZgJvAcSIFELs5oUPiA+0Y20Pq5v7hWLNFX5wyx0O
         rA5sdlVKb1sTUAmUAaCsMFIuvPvx5KhUwT2GkkeZXLGk5QiXn2UPBLQz7xTuXTwVhqKC
         Umxl4VZSHEkpSaqmtOnFvc1EBqjqZ5DpeLb4Oxnehq5mmfSTfv9ln7zDsWbq7m+J/k/V
         h/PLXLOIXqlImkUtrzRaZEyYId21TUvFmltOFMGG7AX3fLFLqtaTkQzmgRoC5NiyjUGn
         dhDgtL1H7BGSEPws7CrTPQN6Ee/HJoAz2j/vFyfIVjmaHZ39UeLTV2xEEQI/EIp9g+uv
         h8jw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5E58KtWGzMT334elrz8QH/ff1Mr2Y+gzCpedhKKM1Bo=;
        b=pYkbC31EEfw3K2+HBvqS1iEqaxsSLwiaTd/iXHUEsjZpd7z7BpwMvgM9RtpPdubvOj
         Z+d2KPxDg5loulyQRWdzraab9gl241iPChFmklZm+WSMYI+GRVOvrX5joOjt/sFlBpIC
         AWFM8mwlD2WRkkkjx3Sotbfztlm7bCwPmYdFEOHLRspM15tq71Dcj2//5DT8Gbhyl1VF
         inugSgs2sSPC1TBdEapViaazHwOnPhedpYrwbUlL4LqwixtT9v8tkHgSWMjtUVQSSu5m
         2dp2zZMC0r6waIofGA9GOqIgMurAeg7YYoLZCGOMBVRTqiIlTiyoedmh3BdbpXBUMi7X
         Erhw==
X-Gm-Message-State: AOAM531PFcVpjAHUxu1bpLuBa79dThyHXWpB09Q1Vh8b0EzCqT+ugWBQ
	BIqwrkHi6DjEngdNGFrViKY=
X-Google-Smtp-Source: ABdhPJxfemOMHCalz1hDiM4SP2ndYj1w0OPxifJl32/mvb4eKsML6GkR+7AqJtQx5Bor5SYVqwe9Jg==
X-Received: by 2002:a25:3244:: with SMTP id y65mr5238601yby.193.1632404664044;
        Thu, 23 Sep 2021 06:44:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b981:: with SMTP id r1ls2943762ybg.8.gmail; Thu, 23 Sep
 2021 06:44:23 -0700 (PDT)
X-Received: by 2002:a25:7e81:: with SMTP id z123mr5772434ybc.64.1632404663520;
        Thu, 23 Sep 2021 06:44:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632404663; cv=none;
        d=google.com; s=arc-20160816;
        b=O4hObm/H4269fWGDBY+znJ+IY22tE7+62UWzR31OEYmlpgQJKJgNF+3nrUOLEA+zPa
         Tm0vUL1eAW2RELvt9xDFfaOaMoouGb28lRsmggajSC3XM00tmfQOTg1dQvAxIdAWheyI
         PI3zubHoqb+Eix29/EH4L6j/LgBAXofFkrARRariFS83LIpm2BwdbapdcZC1zq/BaUeJ
         HjlxVhLHfHR4deD6Gwj+gOb7k20th8TyvjguNALnXGWVbvg06ZSRYWJkJzhXmLYrzTBj
         FDK+VWiKz/pbpfycWKeGrfZFTnYiVbIxRRZNZiYGCMPEWrZwrFb3MkDvhRnuk9GNJ2Ny
         nkqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ukweXmx4e+IJqf+FzCzZ1AIpQAkTlQYs/+7Ou4M2RuM=;
        b=kqcTOjPaz1VB052pX8Nqg8yhSAXBG+v/4M4+8lpwCBZyvbjSU+OmRg4+INxDgKgE9I
         30kfi0jGj+H9tAUyXiVu5nIhwjZ3EAyhwrh2/Hc0XltX93o/CUGRgoY3AXE2GLxJXSQF
         8V8CIymIQWC2ACyfztsggqI3k+vz+fzUxKMoUZJeGtNuHndqs1Yv+lMG9QdczIF51eiS
         cJffLIrXTWS++0WtWnkupsAUW083GE2oPjgfnIS1mW7oR/S/s69wnfWH9x589p+zAszg
         zRsxNZxpMQcWa0r0LM22jP+tqEUYUwlztG+jlWUmlOPs7JZEfnd/sZubtSOE+p6w6s6d
         qkqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="LWu70/eB";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x330.google.com (mail-ot1-x330.google.com. [2607:f8b0:4864:20::330])
        by gmr-mx.google.com with ESMTPS id v16si414696ybq.5.2021.09.23.06.44.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Sep 2021 06:44:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) client-ip=2607:f8b0:4864:20::330;
Received: by mail-ot1-x330.google.com with SMTP id j11-20020a9d190b000000b00546fac94456so8547464ota.6
        for <kasan-dev@googlegroups.com>; Thu, 23 Sep 2021 06:44:23 -0700 (PDT)
X-Received: by 2002:a9d:135:: with SMTP id 50mr4326659otu.295.1632404662778;
 Thu, 23 Sep 2021 06:44:22 -0700 (PDT)
MIME-Version: 1.0
References: <20210923104803.2620285-1-elver@google.com> <20210923104803.2620285-4-elver@google.com>
 <CACT4Y+Zvm4dXQY2tCuypso9aU97_6U2dLhfg2NNA8GTvcQoCLQ@mail.gmail.com> <CAG_fn=V31jEBeEVh0H2+uPAd2AhV9y6hYJmcP0P_i05UJ+MiTg@mail.gmail.com>
In-Reply-To: <CAG_fn=V31jEBeEVh0H2+uPAd2AhV9y6hYJmcP0P_i05UJ+MiTg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 23 Sep 2021 15:44:10 +0200
Message-ID: <CANpmjNOh0ugPq90cVRPAbR-6qr=Q4CsQ_R1Qxk_Bi4TocgwUQA@mail.gmail.com>
Subject: Re: [PATCH v3 4/5] kfence: limit currently covered allocations when
 pool nearly full
To: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Jann Horn <jannh@google.com>, Aleksandr Nogikh <nogikh@google.com>, 
	Taras Madan <tarasmadan@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="LWu70/eB";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as
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

On Thu, 23 Sept 2021 at 15:24, Alexander Potapenko <glider@google.com> wrote:
>
> On Thu, Sep 23, 2021 at 1:19 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Thu, 23 Sept 2021 at 12:48, Marco Elver <elver@google.com> wrote:
> > >
> > > One of KFENCE's main design principles is that with increasing uptime,
> > > allocation coverage increases sufficiently to detect previously
> > > undetected bugs.
> > >
> > > We have observed that frequent long-lived allocations of the same
> > > source (e.g. pagecache) tend to permanently fill up the KFENCE pool
> > > with increasing system uptime, thus breaking the above requirement.
> > > The workaround thus far had been increasing the sample interval and/or
> > > increasing the KFENCE pool size, but is no reliable solution.
> > >
> > > To ensure diverse coverage of allocations, limit currently covered
> > > allocations of the same source once pool utilization reaches 75%
> > > (configurable via `kfence.skip_covered_thresh`) or above. The effect is
> > > retaining reasonable allocation coverage when the pool is close to full.
> > >
> > > A side-effect is that this also limits frequent long-lived allocations
> > > of the same source filling up the pool permanently.
> > >
> > > Uniqueness of an allocation for coverage purposes is based on its
> > > (partial) allocation stack trace (the source). A Counting Bloom filter
> > > is used to check if an allocation is covered; if the allocation is
> > > currently covered, the allocation is skipped by KFENCE.
> > >
> > > Testing was done using:
> > >
> > >         (a) a synthetic workload that performs frequent long-lived
> > >             allocations (default config values; sample_interval=1;
> > >             num_objects=63), and
> > >
> > >         (b) normal desktop workloads on an otherwise idle machine where
> > >             the problem was first reported after a few days of uptime
> > >             (default config values).
> > >
> > > In both test cases the sampled allocation rate no longer drops to zero
> > > at any point. In the case of (b) we observe (after 2 days uptime) 15%
> > > unique allocations in the pool, 77% pool utilization, with 20% "skipped
> > > allocations (covered)".
> > >
> > > Signed-off-by: Marco Elver <elver@google.com>
> >
> > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Acked-by: Alexander Potapenko <glider@google.com>

Thank you both!

> > > ---
> > > v3:
> > > * Remove unneeded !alloc_stack_hash checks.
> > > * Remove unneeded meta->alloc_stack_hash=0 in kfence_guarded_free().
> > >
> > > v2:
> > > * Switch to counting bloom filter to guarantee currently covered
> > >   allocations being skipped.
> > > * Use a module param for skip_covered threshold.
> > > * Use kfence pool address as hash entropy.
> > > * Use filter_irq_stacks().
> > > ---
> > >  mm/kfence/core.c   | 103 ++++++++++++++++++++++++++++++++++++++++++++-
> > >  mm/kfence/kfence.h |   2 +
> > >  2 files changed, 103 insertions(+), 2 deletions(-)
> > >
> > > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > > index db01814f8ff0..58a0f6f1acc5 100644
> > > --- a/mm/kfence/core.c
> > > +++ b/mm/kfence/core.c
> > > @@ -11,11 +11,13 @@
> > >  #include <linux/bug.h>
> > >  #include <linux/debugfs.h>
> > >  #include <linux/irq_work.h>
> > > +#include <linux/jhash.h>
> > >  #include <linux/kcsan-checks.h>
> > >  #include <linux/kfence.h>
> > >  #include <linux/kmemleak.h>
> > >  #include <linux/list.h>
> > >  #include <linux/lockdep.h>
> > > +#include <linux/log2.h>
> > >  #include <linux/memblock.h>
> > >  #include <linux/moduleparam.h>
> > >  #include <linux/random.h>
> > > @@ -82,6 +84,10 @@ static const struct kernel_param_ops sample_interval_param_ops = {
> > >  };
> > >  module_param_cb(sample_interval, &sample_interval_param_ops, &kfence_sample_interval, 0600);
> > >
> > > +/* Pool usage% threshold when currently covered allocations are skipped. */
> > > +static unsigned long kfence_skip_covered_thresh __read_mostly = 75;
> > > +module_param_named(skip_covered_thresh, kfence_skip_covered_thresh, ulong, 0644);
> > > +
> > >  /* The pool of pages used for guard pages and objects. */
> > >  char *__kfence_pool __ro_after_init;
> > >  EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
> > > @@ -105,6 +111,25 @@ DEFINE_STATIC_KEY_FALSE(kfence_allocation_key);
> > >  /* Gates the allocation, ensuring only one succeeds in a given period. */
> > >  atomic_t kfence_allocation_gate = ATOMIC_INIT(1);
> > >
> > > +/*
> > > + * A Counting Bloom filter of allocation coverage: limits currently covered
> > > + * allocations of the same source filling up the pool.
> > > + *
> > > + * Assuming a range of 15%-85% unique allocations in the pool at any point in
>
> Where do these 85% come from?

An imaginary worst case, just to illustrate the range of the false
positive probabilities (in the case of 85% it'd be 0.33). I expect
unique allocations to be around 10-15% on a freshly booted system (on
my real-system-experiment it stayed below 15%), but other workloads
may produce other unique allocations%.

> > > + * time, the below parameters provide a probablity of 0.02-0.33 for false
> > > + * positive hits respectively:
> > > + *
> > > + *     P(alloc_traces) = (1 - e^(-HNUM * (alloc_traces / SIZE)) ^ HNUM
> > > + */
> > > +#define ALLOC_COVERED_HNUM     2
> > > +#define ALLOC_COVERED_SIZE     (1 << (const_ilog2(CONFIG_KFENCE_NUM_OBJECTS) + 2))
> > > +#define ALLOC_COVERED_HNEXT(h) (1664525 * (h) + 1013904223)
>
> Unless we are planning to change these primes, can you use
> next_pseudo_random32() instead?

I'm worried about next_pseudo_random32() changing their implementation
to longer be deterministic or change in other ways that break our
usecase. In this case we want pseudorandomness, but we're not
implementing a PRNG.

Open-coding the constants (given they are from "Numerical Recipes") is
more reliable and doesn't introduce unwanted reliance on
next_pseudo_random32()'s behaviour.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOh0ugPq90cVRPAbR-6qr%3DQ4CsQ_R1Qxk_Bi4TocgwUQA%40mail.gmail.com.
