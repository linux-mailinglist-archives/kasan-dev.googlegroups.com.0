Return-Path: <kasan-dev+bncBCCMH5WKTMGRBT4KWKFAMGQEL2EEXOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id A0C4541603C
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 15:46:56 +0200 (CEST)
Received: by mail-ua1-x937.google.com with SMTP id 14-20020ab0008e000000b002c3861ea14bsf2235082uaj.5
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 06:46:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632404815; cv=pass;
        d=google.com; s=arc-20160816;
        b=OXiMlzqMhYTP9SteqQVm+PunX/Zot3w0rqSoOLdXQfzfelmG0I7zk5TALmC51lD7Ky
         n8xQiWKohBqtseqLRRNJO4uL/AQdFyb++zO5h1uWNt3y0waFuvUYEQiT9xnKlSXM7HR4
         I45CksSgavh7mRq4j+3jz5RMOgqJifp0Ayh2OFWwc/0+yqOfbWgLzsAr7oELQZu45LTf
         s/7p7p5ma50KT5aWwfPFbabJMaREz+1ac8xvRAQu05IM3WC0CjKrJL4X+hi+PiXa5gSv
         MQnbJgqhTpwMngqAAI6OMC93LqfEXmdYRhEzUPEu1E/6aRm9609EWMpGW9MtG4fD3U1z
         Mxog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aqiHpNj+v43SQ06RI8D18xMpUaxGlNpu84enZbwzgQw=;
        b=yNPVCMqsuIk6KoNLDYrdIQ4ApaAgAu8JR+G6dmp3Zeafu6D376Fb2+nCRSOnquXmDE
         +1OK4GHdD+hUGQ87AvzHOa4of89snAXLKCbdeZ2aK84C19geaBWmbWvK0jzQ1QH4hITu
         /YngEykVSDn8iKLRBlEzJ4MdF63YSeuP2hPPtHj7af2FEicesRI0zQqTBfgKzm0lDY6j
         YJKC6ihvh08l0WPMZGs78Fgutlr/ww3zTFE/uspKcxbHNuSLfOIxgwezPePvXsKhQ/FT
         0GMDACtxDcwOrhzluXYZFXWOrtWCzFsbG1MhoHmoqBsU1W/kvOXf0L0kXqKEmE02/UDF
         UyBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hDlU7ifN;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=aqiHpNj+v43SQ06RI8D18xMpUaxGlNpu84enZbwzgQw=;
        b=MeHwIjLPd2JpktqZUPcYd3hHzHUo7NhXU02O4Ll9qwT05aZVRypuIGHr9f8GuV8/XJ
         TAVGXEXmu1IKIGBp3NNUkXgX6fYhJMrBdYizl3Tswr/DnfoJ8ydE+da6ZzWCICEDo/Ik
         gM0IKSYUgWKN23YwKzoTXcf9eujxgHvUVHJBDbdTYei8KYcyriKvW6yRYSzylJ33FbCp
         2fQXgU/uxbBNg9HhF56Rp94g8EI+MFYbqPpgCy25t8/qWRb6MdjZRuQgy8GJnWSGMI7g
         5Jrc6OR05XjRTCoSVLDjeb4q1Dclko/xzGmqKMnkShllsoUzuNdWlyPLoGHFTQlMl4ZT
         HxSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aqiHpNj+v43SQ06RI8D18xMpUaxGlNpu84enZbwzgQw=;
        b=xF2/oFh73RLgQHqrYlZavLbMWJjDDnywyGhliEI3XqhW4OgU/aLR5td01tYIFnIaMh
         QaGRb2DJDUikIrS0CrUbFS6NBQGi/7SgjWb4SlRvf4h7IAiaJvTgisdsZ+sIgMjK9mkd
         PTpU652SNsU/rm/zTW1IvhqYAc4jaD0L5PZU/lE/V//TX3R43AwsPCD+suVFPW/v2ioP
         55oPB4+ile8Bif3kucgIN2y5bBJSF8NputNdZd0hbEKH7tl6jfTweLXWRjQPY2rn5kls
         vwahILeDg908JR09nvMDvtapmVmcrnyYZ2EOS76qLMolOAfwtZx/BuKtZE1x6+rT6jft
         d9NQ==
X-Gm-Message-State: AOAM533a/txDG639BBE2/Q6oirJMS8lm6fSKClVf2U4O/9yO1XjoA+hi
	NzQOdVPHbuIAmHAq3NHm428=
X-Google-Smtp-Source: ABdhPJw3nWfyNj7S+RtnYVIRXgawcsU2Sux6D+d13nvW6aVZShW0zaQpo0gXhM4DBScPvIfgkw5rtw==
X-Received: by 2002:a67:a644:: with SMTP id r4mr4267815vsh.24.1632404815534;
        Thu, 23 Sep 2021 06:46:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:2dd4:: with SMTP id t203ls526607vkt.11.gmail; Thu, 23
 Sep 2021 06:46:55 -0700 (PDT)
X-Received: by 2002:a1f:9ec3:: with SMTP id h186mr3598986vke.5.1632404815015;
        Thu, 23 Sep 2021 06:46:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632404815; cv=none;
        d=google.com; s=arc-20160816;
        b=YV0JZkMiWj1k2RtUxxA/p8F9abJfD7k0fjTEMmRnGznQ5Qoxa3zNUSw+55Fc9X2KPt
         WaPzOGhxemkNvYxZyzjeOiAMw8wYY/MG7gsdLrE9BIyusU2EdmZEG9eZ/lCZJBcALjFb
         TWQ/FEfVtenpT2Pdp+UJI5EsMocs3VEEozXZ00m5D5wydXi3mgjzqrjweYMrm1CRURWo
         CSakfwCT4B7zt1TdI+8jjTPsKb+ndFtNeiBLDhlA2NKVZbBlGqxt07hLA666wIkC4ZSS
         9Tc2DjWyiHc8b7E4Azn5HzP0IIJj4kF5H8Q1rA43Z+Z0NZPLLHvb3L4EQ08F42/un63U
         HjrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dR924fzJUnTOwFpFaOiKPGo+uYxMThczPIp4R0ax1KE=;
        b=PLo94umtDHYTHosE7Q8PXb8ToyeCVltCDdeNyWgKlZOvsnDuuJKjtqCv9TA74Pox0L
         QnkEIA6qd3zxKM+Tf0BmFEboQY3hsSkQ/bCO6J2gtG19pe/vhzqKK+s6fvMn0YotxGJU
         idGJsOl/M+J2+jpt8bHkv5ntNQp9675uuG7m/e4tsDDy6Khf83aCmERYSazufi0LQRmU
         uCAaqJSDJjRrDNQBYZLUAqI2jeJhDhb6h3iI0WVwhpaay9mi1gfc2V+0eSfvATMHUCXo
         CXGyjgHhlGwSjDvOtK5nSq4GmS51Tz2YwxwGV3i3EtXTF/D4h6se5zHqAAs1SNc2/Rvs
         0z0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hDlU7ifN;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2c.google.com (mail-qv1-xf2c.google.com. [2607:f8b0:4864:20::f2c])
        by gmr-mx.google.com with ESMTPS id j65si312170vkj.1.2021.09.23.06.46.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Sep 2021 06:46:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) client-ip=2607:f8b0:4864:20::f2c;
Received: by mail-qv1-xf2c.google.com with SMTP id a12so4147808qvz.4
        for <kasan-dev@googlegroups.com>; Thu, 23 Sep 2021 06:46:54 -0700 (PDT)
X-Received: by 2002:a05:6214:6b0:: with SMTP id s16mr4427451qvz.61.1632404814437;
 Thu, 23 Sep 2021 06:46:54 -0700 (PDT)
MIME-Version: 1.0
References: <20210923104803.2620285-1-elver@google.com> <20210923104803.2620285-4-elver@google.com>
 <CACT4Y+Zvm4dXQY2tCuypso9aU97_6U2dLhfg2NNA8GTvcQoCLQ@mail.gmail.com>
 <CAG_fn=V31jEBeEVh0H2+uPAd2AhV9y6hYJmcP0P_i05UJ+MiTg@mail.gmail.com> <CANpmjNOh0ugPq90cVRPAbR-6qr=Q4CsQ_R1Qxk_Bi4TocgwUQA@mail.gmail.com>
In-Reply-To: <CANpmjNOh0ugPq90cVRPAbR-6qr=Q4CsQ_R1Qxk_Bi4TocgwUQA@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 23 Sep 2021 15:46:17 +0200
Message-ID: <CAG_fn=VpgmcmLg7=bh6Mf6HNr6wZYUADJZfB5AuRkedCqas6-w@mail.gmail.com>
Subject: Re: [PATCH v3 4/5] kfence: limit currently covered allocations when
 pool nearly full
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Jann Horn <jannh@google.com>, Aleksandr Nogikh <nogikh@google.com>, 
	Taras Madan <tarasmadan@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hDlU7ifN;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2c as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Sep 23, 2021 at 3:44 PM Marco Elver <elver@google.com> wrote:
>
> On Thu, 23 Sept 2021 at 15:24, Alexander Potapenko <glider@google.com> wr=
ote:
> >
> > On Thu, Sep 23, 2021 at 1:19 PM Dmitry Vyukov <dvyukov@google.com> wrot=
e:
> > >
> > > On Thu, 23 Sept 2021 at 12:48, Marco Elver <elver@google.com> wrote:
> > > >
> > > > One of KFENCE's main design principles is that with increasing upti=
me,
> > > > allocation coverage increases sufficiently to detect previously
> > > > undetected bugs.
> > > >
> > > > We have observed that frequent long-lived allocations of the same
> > > > source (e.g. pagecache) tend to permanently fill up the KFENCE pool
> > > > with increasing system uptime, thus breaking the above requirement.
> > > > The workaround thus far had been increasing the sample interval and=
/or
> > > > increasing the KFENCE pool size, but is no reliable solution.
> > > >
> > > > To ensure diverse coverage of allocations, limit currently covered
> > > > allocations of the same source once pool utilization reaches 75%
> > > > (configurable via `kfence.skip_covered_thresh`) or above. The effec=
t is
> > > > retaining reasonable allocation coverage when the pool is close to =
full.
> > > >
> > > > A side-effect is that this also limits frequent long-lived allocati=
ons
> > > > of the same source filling up the pool permanently.
> > > >
> > > > Uniqueness of an allocation for coverage purposes is based on its
> > > > (partial) allocation stack trace (the source). A Counting Bloom fil=
ter
> > > > is used to check if an allocation is covered; if the allocation is
> > > > currently covered, the allocation is skipped by KFENCE.
> > > >
> > > > Testing was done using:
> > > >
> > > >         (a) a synthetic workload that performs frequent long-lived
> > > >             allocations (default config values; sample_interval=3D1=
;
> > > >             num_objects=3D63), and
> > > >
> > > >         (b) normal desktop workloads on an otherwise idle machine w=
here
> > > >             the problem was first reported after a few days of upti=
me
> > > >             (default config values).
> > > >
> > > > In both test cases the sampled allocation rate no longer drops to z=
ero
> > > > at any point. In the case of (b) we observe (after 2 days uptime) 1=
5%
> > > > unique allocations in the pool, 77% pool utilization, with 20% "ski=
pped
> > > > allocations (covered)".
> > > >
> > > > Signed-off-by: Marco Elver <elver@google.com>
> > >
> > > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > Acked-by: Alexander Potapenko <glider@google.com>
>
> Thank you both!
>
> > > > ---
> > > > v3:
> > > > * Remove unneeded !alloc_stack_hash checks.
> > > > * Remove unneeded meta->alloc_stack_hash=3D0 in kfence_guarded_free=
().
> > > >
> > > > v2:
> > > > * Switch to counting bloom filter to guarantee currently covered
> > > >   allocations being skipped.
> > > > * Use a module param for skip_covered threshold.
> > > > * Use kfence pool address as hash entropy.
> > > > * Use filter_irq_stacks().
> > > > ---
> > > >  mm/kfence/core.c   | 103 +++++++++++++++++++++++++++++++++++++++++=
+++-
> > > >  mm/kfence/kfence.h |   2 +
> > > >  2 files changed, 103 insertions(+), 2 deletions(-)
> > > >
> > > > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > > > index db01814f8ff0..58a0f6f1acc5 100644
> > > > --- a/mm/kfence/core.c
> > > > +++ b/mm/kfence/core.c
> > > > @@ -11,11 +11,13 @@
> > > >  #include <linux/bug.h>
> > > >  #include <linux/debugfs.h>
> > > >  #include <linux/irq_work.h>
> > > > +#include <linux/jhash.h>
> > > >  #include <linux/kcsan-checks.h>
> > > >  #include <linux/kfence.h>
> > > >  #include <linux/kmemleak.h>
> > > >  #include <linux/list.h>
> > > >  #include <linux/lockdep.h>
> > > > +#include <linux/log2.h>
> > > >  #include <linux/memblock.h>
> > > >  #include <linux/moduleparam.h>
> > > >  #include <linux/random.h>
> > > > @@ -82,6 +84,10 @@ static const struct kernel_param_ops sample_inte=
rval_param_ops =3D {
> > > >  };
> > > >  module_param_cb(sample_interval, &sample_interval_param_ops, &kfen=
ce_sample_interval, 0600);
> > > >
> > > > +/* Pool usage% threshold when currently covered allocations are sk=
ipped. */
> > > > +static unsigned long kfence_skip_covered_thresh __read_mostly =3D =
75;
> > > > +module_param_named(skip_covered_thresh, kfence_skip_covered_thresh=
, ulong, 0644);
> > > > +
> > > >  /* The pool of pages used for guard pages and objects. */
> > > >  char *__kfence_pool __ro_after_init;
> > > >  EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
> > > > @@ -105,6 +111,25 @@ DEFINE_STATIC_KEY_FALSE(kfence_allocation_key)=
;
> > > >  /* Gates the allocation, ensuring only one succeeds in a given per=
iod. */
> > > >  atomic_t kfence_allocation_gate =3D ATOMIC_INIT(1);
> > > >
> > > > +/*
> > > > + * A Counting Bloom filter of allocation coverage: limits currentl=
y covered
> > > > + * allocations of the same source filling up the pool.
> > > > + *
> > > > + * Assuming a range of 15%-85% unique allocations in the pool at a=
ny point in
> >
> > Where do these 85% come from?
>
> An imaginary worst case, just to illustrate the range of the false
> positive probabilities (in the case of 85% it'd be 0.33). I expect
> unique allocations to be around 10-15% on a freshly booted system (on
> my real-system-experiment it stayed below 15%), but other workloads
> may produce other unique allocations%.
>
> > > > + * time, the below parameters provide a probablity of 0.02-0.33 fo=
r false
> > > > + * positive hits respectively:
> > > > + *
> > > > + *     P(alloc_traces) =3D (1 - e^(-HNUM * (alloc_traces / SIZE)) =
^ HNUM
> > > > + */
> > > > +#define ALLOC_COVERED_HNUM     2
> > > > +#define ALLOC_COVERED_SIZE     (1 << (const_ilog2(CONFIG_KFENCE_NU=
M_OBJECTS) + 2))
> > > > +#define ALLOC_COVERED_HNEXT(h) (1664525 * (h) + 1013904223)
> >
> > Unless we are planning to change these primes, can you use
> > next_pseudo_random32() instead?
>
> I'm worried about next_pseudo_random32() changing their implementation
> to longer be deterministic or change in other ways that break our
> usecase. In this case we want pseudorandomness, but we're not
> implementing a PRNG.
>
> Open-coding the constants (given they are from "Numerical Recipes") is
> more reliable and doesn't introduce unwanted reliance on
> next_pseudo_random32()'s behaviour.

Okay, fair enough.

>
> Thanks,
> -- Marco



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVpgmcmLg7%3Dbh6Mf6HNr6wZYUADJZfB5AuRkedCqas6-w%40mail.gm=
ail.com.
