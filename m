Return-Path: <kasan-dev+bncBCCMH5WKTMGRBAMAWKFAMGQET6R4XYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A015415F9E
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 15:24:18 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id w17-20020ae9e511000000b00431497430b7sf19004910qkf.12
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 06:24:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632403457; cv=pass;
        d=google.com; s=arc-20160816;
        b=XKjyXpmTRSI4L67Muh70z5StRMpkeL9HtRN5wdjGB75h+I5PctmSWv3MeOVufmWbph
         4iAX1pexokexq/eJSb3gkqOMicPV/+fvTdafywg7PKY2MzCfZGuHmsVktua97L13kcHZ
         nfIGsOnGFCTHuSRHnIbbdU+fSz6eJFxz6VjkgKNmx+WUjOJB8HhYrGznFskHHkSLZ7bQ
         1Nc4Frvr+e2efx+ZYDBSrBhob8yrhr3ZRaKNUzr2v553WB63z6QWu1euExhf5umv/v4t
         je4267wVEK3ik0zsC+aSqh8i5ou/u4UpJTdWYfgqrQjPVhiTEOapBOOfEE6E+haAm/R9
         459g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DbQ1/dsiyzhm3OXvJnbyfeKR7q6uGX2X9DCAW6Aen+Q=;
        b=m72WnOWO/L7C/R4bmuOCiLNjbIWLYAJmQICnWx4xCfyvCWcoKU4e9Dtqq4VIMEc2MX
         eh3At4JMRWEDtrYNaLJVeNTuSTAd78isl7IgEEZdAKXLnIag72bMx5AAi26JM0FqRBg6
         5bk0YJRtHQBRwz9tr2oP/HVdsTqaET9eOeyI97MfnDLLN5OIYWVVv/dC/oyntADfJcIg
         YTvuv0oSBWdUCmybUw6CRmbbzE/gAZqvrOlcMky4Ixi7+SkJShj09857sYUo/4G3B1ON
         wrtUBT5wQ0OfqMMcr2HTSUrMaMt31JAaTODZbrlT2ReGhHyFU7F3RwKX94ecxMI0wapd
         xKBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=E4bTKRFT;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=DbQ1/dsiyzhm3OXvJnbyfeKR7q6uGX2X9DCAW6Aen+Q=;
        b=f1Uq/rEsrobl6nv9G+kgpeMf9B3ZdoSo3TlfQdjmyY2yOS+IswrOfIt94J9e5LyRjl
         z3soKs1FPmlfhe8Op/g5qlaHW1KpHfK7wi4filBpJfANsJyS2dxFAK3p2YCGQOkKtkKj
         /ibX9IrXB+paiTvrtklPAxIZ31GJlAV+DBs1fBNR8z3hPaJ0cTgl3jfMhJYndDGyqW+3
         T17MU/FzTj43WRp8L3Bh5MNG/Z8JfcU9b0uUmQGblRChfG2BVY5SjiaVzK56LaPP83ZJ
         niVOyU8HkpqnOv8XH8pYKDvc0yAPXkBZibJFZ595fYDKdadJ171op0YoOHPvSGrfebwK
         N4kA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DbQ1/dsiyzhm3OXvJnbyfeKR7q6uGX2X9DCAW6Aen+Q=;
        b=bJUFXViwa412tUShzBSyS+9flzWPzKOrIdukGkyzqgIntlpEbZ+5dZXppCbbeLS3GL
         iSL+QWs7VWjJO7c+nyXBrhJlCDoos4aquKxqx5WYM3jso2LPkmU6WpUjIZg2OrGUHNVo
         XzLNe9ZOyodh0kU+4jI5Ed55qw33rImWK1L2WetGK5AjNEQVjaT8AZngp2kxMA28j70P
         +FanbpZXBpysx1nAA6IRAVcuwa6djooc2DCeNsqp2b0u40JoCSGWz4C46zfyaNn0UTCs
         eDXxaPiN94gMCzi/jXtWGaR82puXXtYNYbPHqZUs8SSPOk/uVGjuHmpkA+IFnxWcfMg2
         DGMQ==
X-Gm-Message-State: AOAM532on5Xp2qja8Pi7B2rUQ0VQGg98XsUrOaZA7VdK5ZEqgV8icmWV
	la32PhKB/GZz/uqit/gRKVc=
X-Google-Smtp-Source: ABdhPJzldmKhh/gH4Uz/vDsclXpEqRPZ5vindhRtacUD8V90O+smTY5xXwaphwI2k+rXjgFaIjQPSg==
X-Received: by 2002:ac8:7d8b:: with SMTP id c11mr4735070qtd.45.1632403457696;
        Thu, 23 Sep 2021 06:24:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:dd82:: with SMTP id v2ls1961232qvk.2.gmail; Thu, 23 Sep
 2021 06:24:17 -0700 (PDT)
X-Received: by 2002:ad4:4671:: with SMTP id z17mr4443644qvv.62.1632403457159;
        Thu, 23 Sep 2021 06:24:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632403457; cv=none;
        d=google.com; s=arc-20160816;
        b=jXep144XeEzS0I2JwQgMI+PGZ6H7WEdhTh2eRzMzN/Wpbx0O+ziP9yRvrhwkIs3/qt
         pZWghmZweaK2o+mre6AowWQTZ6WMmLuZ9OcgYGxsNHJcVKaccuMH5Eusu2VPHHoHVjSS
         PqUuInrIorMcqhmGXbxQmx960JyoF0depRjV4P0MIpEnHzIaVzC1bZ7WesHYZU/BFJxl
         uyojgtA2HpU8kKYU+1sRINzsBB5ZU/llx+eK2fOxwrIjC3vEIeW0KPjvjU/a0H0Y14mE
         62TESDEx0ZVLAdhDV8ETcM2y1KKW/0PIDcCyxt6raFH5bgRySQQ/CDaUdKxtRLYQpSSc
         rang==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=9u6DpipKdkYxzryu97JGWR+FHzvdxp/0hUwzm5Xllkg=;
        b=tES10sy4SZIBgO91GS9lMDgTuL1DYq8noWnS1IzHO6caUaKSM+AooFb2hPQZry91YJ
         mA6UyIPjzabx+vFnpobfVE048VM2tIISMI5DYZEQlYoFswrIE+JqdDsObkRFPWxOptyY
         euAjNW7WQEVAX5tPWKLjIkITmZAw5K5xavDvVPxxTGSYRYHZefVLHoqpUe9omwWac3mo
         6WyH/kSZhH2jWl/oTYMv/BHezBJOcNhv1hvDATDt7geD+9vv2FdOPx2FCYa5FUDxvqr5
         oWSrjomtz7iXPLPdFUV9jua+lL3CremFZuI8uAjxEN64ER7R+z/F47/DdnQ76IBjwmX3
         2Qkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=E4bTKRFT;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x834.google.com (mail-qt1-x834.google.com. [2607:f8b0:4864:20::834])
        by gmr-mx.google.com with ESMTPS id n27si707646qtl.4.2021.09.23.06.24.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Sep 2021 06:24:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::834 as permitted sender) client-ip=2607:f8b0:4864:20::834;
Received: by mail-qt1-x834.google.com with SMTP id d8so6106440qtd.5
        for <kasan-dev@googlegroups.com>; Thu, 23 Sep 2021 06:24:17 -0700 (PDT)
X-Received: by 2002:ac8:560b:: with SMTP id 11mr4779099qtr.319.1632403456468;
 Thu, 23 Sep 2021 06:24:16 -0700 (PDT)
MIME-Version: 1.0
References: <20210923104803.2620285-1-elver@google.com> <20210923104803.2620285-4-elver@google.com>
 <CACT4Y+Zvm4dXQY2tCuypso9aU97_6U2dLhfg2NNA8GTvcQoCLQ@mail.gmail.com>
In-Reply-To: <CACT4Y+Zvm4dXQY2tCuypso9aU97_6U2dLhfg2NNA8GTvcQoCLQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 23 Sep 2021 15:23:39 +0200
Message-ID: <CAG_fn=V31jEBeEVh0H2+uPAd2AhV9y6hYJmcP0P_i05UJ+MiTg@mail.gmail.com>
Subject: Re: [PATCH v3 4/5] kfence: limit currently covered allocations when
 pool nearly full
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Jann Horn <jannh@google.com>, Aleksandr Nogikh <nogikh@google.com>, 
	Taras Madan <tarasmadan@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=E4bTKRFT;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::834 as
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

On Thu, Sep 23, 2021 at 1:19 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, 23 Sept 2021 at 12:48, Marco Elver <elver@google.com> wrote:
> >
> > One of KFENCE's main design principles is that with increasing uptime,
> > allocation coverage increases sufficiently to detect previously
> > undetected bugs.
> >
> > We have observed that frequent long-lived allocations of the same
> > source (e.g. pagecache) tend to permanently fill up the KFENCE pool
> > with increasing system uptime, thus breaking the above requirement.
> > The workaround thus far had been increasing the sample interval and/or
> > increasing the KFENCE pool size, but is no reliable solution.
> >
> > To ensure diverse coverage of allocations, limit currently covered
> > allocations of the same source once pool utilization reaches 75%
> > (configurable via `kfence.skip_covered_thresh`) or above. The effect is
> > retaining reasonable allocation coverage when the pool is close to full=
.
> >
> > A side-effect is that this also limits frequent long-lived allocations
> > of the same source filling up the pool permanently.
> >
> > Uniqueness of an allocation for coverage purposes is based on its
> > (partial) allocation stack trace (the source). A Counting Bloom filter
> > is used to check if an allocation is covered; if the allocation is
> > currently covered, the allocation is skipped by KFENCE.
> >
> > Testing was done using:
> >
> >         (a) a synthetic workload that performs frequent long-lived
> >             allocations (default config values; sample_interval=3D1;
> >             num_objects=3D63), and
> >
> >         (b) normal desktop workloads on an otherwise idle machine where
> >             the problem was first reported after a few days of uptime
> >             (default config values).
> >
> > In both test cases the sampled allocation rate no longer drops to zero
> > at any point. In the case of (b) we observe (after 2 days uptime) 15%
> > unique allocations in the pool, 77% pool utilization, with 20% "skipped
> > allocations (covered)".
> >
> > Signed-off-by: Marco Elver <elver@google.com>
>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Alexander Potapenko <glider@google.com>

>
> > ---
> > v3:
> > * Remove unneeded !alloc_stack_hash checks.
> > * Remove unneeded meta->alloc_stack_hash=3D0 in kfence_guarded_free().
> >
> > v2:
> > * Switch to counting bloom filter to guarantee currently covered
> >   allocations being skipped.
> > * Use a module param for skip_covered threshold.
> > * Use kfence pool address as hash entropy.
> > * Use filter_irq_stacks().
> > ---
> >  mm/kfence/core.c   | 103 ++++++++++++++++++++++++++++++++++++++++++++-
> >  mm/kfence/kfence.h |   2 +
> >  2 files changed, 103 insertions(+), 2 deletions(-)
> >
> > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > index db01814f8ff0..58a0f6f1acc5 100644
> > --- a/mm/kfence/core.c
> > +++ b/mm/kfence/core.c
> > @@ -11,11 +11,13 @@
> >  #include <linux/bug.h>
> >  #include <linux/debugfs.h>
> >  #include <linux/irq_work.h>
> > +#include <linux/jhash.h>
> >  #include <linux/kcsan-checks.h>
> >  #include <linux/kfence.h>
> >  #include <linux/kmemleak.h>
> >  #include <linux/list.h>
> >  #include <linux/lockdep.h>
> > +#include <linux/log2.h>
> >  #include <linux/memblock.h>
> >  #include <linux/moduleparam.h>
> >  #include <linux/random.h>
> > @@ -82,6 +84,10 @@ static const struct kernel_param_ops sample_interval=
_param_ops =3D {
> >  };
> >  module_param_cb(sample_interval, &sample_interval_param_ops, &kfence_s=
ample_interval, 0600);
> >
> > +/* Pool usage% threshold when currently covered allocations are skippe=
d. */
> > +static unsigned long kfence_skip_covered_thresh __read_mostly =3D 75;
> > +module_param_named(skip_covered_thresh, kfence_skip_covered_thresh, ul=
ong, 0644);
> > +
> >  /* The pool of pages used for guard pages and objects. */
> >  char *__kfence_pool __ro_after_init;
> >  EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
> > @@ -105,6 +111,25 @@ DEFINE_STATIC_KEY_FALSE(kfence_allocation_key);
> >  /* Gates the allocation, ensuring only one succeeds in a given period.=
 */
> >  atomic_t kfence_allocation_gate =3D ATOMIC_INIT(1);
> >
> > +/*
> > + * A Counting Bloom filter of allocation coverage: limits currently co=
vered
> > + * allocations of the same source filling up the pool.
> > + *
> > + * Assuming a range of 15%-85% unique allocations in the pool at any p=
oint in

Where do these 85% come from?

> > + * time, the below parameters provide a probablity of 0.02-0.33 for fa=
lse
> > + * positive hits respectively:
> > + *
> > + *     P(alloc_traces) =3D (1 - e^(-HNUM * (alloc_traces / SIZE)) ^ HN=
UM
> > + */
> > +#define ALLOC_COVERED_HNUM     2
> > +#define ALLOC_COVERED_SIZE     (1 << (const_ilog2(CONFIG_KFENCE_NUM_OB=
JECTS) + 2))
> > +#define ALLOC_COVERED_HNEXT(h) (1664525 * (h) + 1013904223)

Unless we are planning to change these primes, can you use
next_pseudo_random32() instead?


> > +#define ALLOC_COVERED_MASK     (ALLOC_COVERED_SIZE - 1)
> > +static atomic_t alloc_covered[ALLOC_COVERED_SIZE];
> > +
> > +/* Stack depth used to determine uniqueness of an allocation. */
> > +#define UNIQUE_ALLOC_STACK_DEPTH 8UL
> > +
> >  /* Statistics counters for debugfs. */
> >  enum kfence_counter_id {
> >         KFENCE_COUNTER_ALLOCATED,
> > @@ -114,6 +139,7 @@ enum kfence_counter_id {
> >         KFENCE_COUNTER_BUGS,
> >         KFENCE_COUNTER_SKIP_INCOMPAT,
> >         KFENCE_COUNTER_SKIP_CAPACITY,
> > +       KFENCE_COUNTER_SKIP_COVERED,
> >         KFENCE_COUNTER_COUNT,
> >  };
> >  static atomic_long_t counters[KFENCE_COUNTER_COUNT];
> > @@ -125,11 +151,60 @@ static const char *const counter_names[] =3D {
> >         [KFENCE_COUNTER_BUGS]           =3D "total bugs",
> >         [KFENCE_COUNTER_SKIP_INCOMPAT]  =3D "skipped allocations (incom=
patible)",
> >         [KFENCE_COUNTER_SKIP_CAPACITY]  =3D "skipped allocations (capac=
ity)",
> > +       [KFENCE_COUNTER_SKIP_COVERED]   =3D "skipped allocations (cover=
ed)",
> >  };
> >  static_assert(ARRAY_SIZE(counter_names) =3D=3D KFENCE_COUNTER_COUNT);
> >
> >  /* =3D=3D=3D Internals =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D */
> >
> > +static inline bool should_skip_covered(void)
> > +{
> > +       unsigned long thresh =3D (CONFIG_KFENCE_NUM_OBJECTS * kfence_sk=
ip_covered_thresh) / 100;
> > +
> > +       return atomic_long_read(&counters[KFENCE_COUNTER_ALLOCATED]) > =
thresh;
> > +}
> > +
> > +static u32 get_alloc_stack_hash(unsigned long *stack_entries, size_t n=
um_entries)
> > +{
> > +       /* Some randomness across reboots / different machines. */
> > +       u32 seed =3D (u32)((unsigned long)__kfence_pool >> (BITS_PER_LO=
NG - 32));
> > +
> > +       num_entries =3D min(num_entries, UNIQUE_ALLOC_STACK_DEPTH);
> > +       num_entries =3D filter_irq_stacks(stack_entries, num_entries);
> > +       return jhash(stack_entries, num_entries * sizeof(stack_entries[=
0]), seed);
> > +}
> > +
> > +/*
> > + * Adds (or subtracts) count @val for allocation stack trace hash
> > + * @alloc_stack_hash from Counting Bloom filter.
> > + */
> > +static void alloc_covered_add(u32 alloc_stack_hash, int val)
> > +{
> > +       int i;
> > +
> > +       for (i =3D 0; i < ALLOC_COVERED_HNUM; i++) {
> > +               atomic_add(val, &alloc_covered[alloc_stack_hash & ALLOC=
_COVERED_MASK]);
> > +               alloc_stack_hash =3D ALLOC_COVERED_HNEXT(alloc_stack_ha=
sh);
> > +       }
> > +}
> > +
> > +/*
> > + * Returns true if the allocation stack trace hash @alloc_stack_hash i=
s
> > + * currently contained (non-zero count) in Counting Bloom filter.
> > + */
> > +static bool alloc_covered_contains(u32 alloc_stack_hash)
> > +{
> > +       int i;
> > +
> > +       for (i =3D 0; i < ALLOC_COVERED_HNUM; i++) {
> > +               if (!atomic_read(&alloc_covered[alloc_stack_hash & ALLO=
C_COVERED_MASK]))
> > +                       return false;
> > +               alloc_stack_hash =3D ALLOC_COVERED_HNEXT(alloc_stack_ha=
sh);
> > +       }
> > +
> > +       return true;
> > +}
> > +
> >  static bool kfence_protect(unsigned long addr)
> >  {
> >         return !KFENCE_WARN_ON(!kfence_protect_page(ALIGN_DOWN(addr, PA=
GE_SIZE), true));
> > @@ -269,7 +344,8 @@ static __always_inline void for_each_canary(const s=
truct kfence_metadata *meta,
> >  }
> >
> >  static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t siz=
e, gfp_t gfp,
> > -                                 unsigned long *stack_entries, size_t =
num_stack_entries)
> > +                                 unsigned long *stack_entries, size_t =
num_stack_entries,
> > +                                 u32 alloc_stack_hash)
> >  {
> >         struct kfence_metadata *meta =3D NULL;
> >         unsigned long flags;
> > @@ -332,6 +408,8 @@ static void *kfence_guarded_alloc(struct kmem_cache=
 *cache, size_t size, gfp_t g
> >         /* Pairs with READ_ONCE() in kfence_shutdown_cache(). */
> >         WRITE_ONCE(meta->cache, cache);
> >         meta->size =3D size;
> > +       meta->alloc_stack_hash =3D alloc_stack_hash;
> > +
> >         for_each_canary(meta, set_canary_byte);
> >
> >         /* Set required struct page fields. */
> > @@ -344,6 +422,8 @@ static void *kfence_guarded_alloc(struct kmem_cache=
 *cache, size_t size, gfp_t g
> >
> >         raw_spin_unlock_irqrestore(&meta->lock, flags);
> >
> > +       alloc_covered_add(alloc_stack_hash, 1);
> > +
> >         /* Memory initialization. */
> >
> >         /*
> > @@ -412,6 +492,8 @@ static void kfence_guarded_free(void *addr, struct =
kfence_metadata *meta, bool z
> >
> >         raw_spin_unlock_irqrestore(&meta->lock, flags);
> >
> > +       alloc_covered_add(meta->alloc_stack_hash, -1);
> > +
> >         /* Protect to detect use-after-frees. */
> >         kfence_protect((unsigned long)addr);
> >
> > @@ -752,6 +834,7 @@ void *__kfence_alloc(struct kmem_cache *s, size_t s=
ize, gfp_t flags)
> >  {
> >         unsigned long stack_entries[KFENCE_STACK_DEPTH];
> >         size_t num_stack_entries;
> > +       u32 alloc_stack_hash;
> >
> >         /*
> >          * Perform size check before switching kfence_allocation_gate, =
so that
> > @@ -799,7 +882,23 @@ void *__kfence_alloc(struct kmem_cache *s, size_t =
size, gfp_t flags)
> >
> >         num_stack_entries =3D stack_trace_save(stack_entries, KFENCE_ST=
ACK_DEPTH, 0);
> >
> > -       return kfence_guarded_alloc(s, size, flags, stack_entries, num_=
stack_entries);
> > +       /*
> > +        * Do expensive check for coverage of allocation in slow-path a=
fter
> > +        * allocation_gate has already become non-zero, even though it =
might
> > +        * mean not making any allocation within a given sample interva=
l.
> > +        *
> > +        * This ensures reasonable allocation coverage when the pool is=
 almost
> > +        * full, including avoiding long-lived allocations of the same =
source
> > +        * filling up the pool (e.g. pagecache allocations).
> > +        */
> > +       alloc_stack_hash =3D get_alloc_stack_hash(stack_entries, num_st=
ack_entries);
> > +       if (should_skip_covered() && alloc_covered_contains(alloc_stack=
_hash)) {
> > +               atomic_long_inc(&counters[KFENCE_COUNTER_SKIP_COVERED])=
;
> > +               return NULL;
> > +       }
> > +
> > +       return kfence_guarded_alloc(s, size, flags, stack_entries, num_=
stack_entries,
> > +                                   alloc_stack_hash);
> >  }
> >
> >  size_t kfence_ksize(const void *addr)
> > diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
> > index c1f23c61e5f9..2a2d5de9d379 100644
> > --- a/mm/kfence/kfence.h
> > +++ b/mm/kfence/kfence.h
> > @@ -87,6 +87,8 @@ struct kfence_metadata {
> >         /* Allocation and free stack information. */
> >         struct kfence_track alloc_track;
> >         struct kfence_track free_track;
> > +       /* For updating alloc_covered on frees. */
> > +       u32 alloc_stack_hash;
> >  };
> >
> >  extern struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECT=
S];
> > --
> > 2.33.0.464.g1972c5931b-goog
> >



--
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
kasan-dev/CAG_fn%3DV31jEBeEVh0H2%2BuPAd2AhV9y6hYJmcP0P_i05UJ%2BMiTg%40mail.=
gmail.com.
