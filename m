Return-Path: <kasan-dev+bncBCMIZB7QWENRBDO7Z36QKGQEBIBWZ5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 864D02B5E00
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 12:10:06 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id w8sf4243876ybq.4
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 03:10:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605611405; cv=pass;
        d=google.com; s=arc-20160816;
        b=RrQxnFc5fF6YdI6rvA84Y4yKQFkDYBVNl2twoQvf3Yu8aijsRfyCj3UJmQJegy/sPR
         XYaOlbTgPUTDJtMGkLDMC4lftKhsEi6HGyImdBxTWXnlZtW9uZLfWl1l4G8J+mYVMflf
         aQofDRQHygiC7TtDYjNBPO5o53LZnmt7ecqbhgKsEDCdq0jSuKJLaNuvISFyM0y6KlG6
         hKANjSbl3ns9D1ry9MRGHnAhg0DRiIHlSljBSa7Fa0SmC80lHPSE/JCYCYY97mDJ6FXW
         usPpJId6hAfNllQ7ZDEPVvISIfGa0A8Fq9YsIw0j7RPFH3UkflPZ0S7hqwGwtOktaPiZ
         ZUgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=x1S+n/33YBtoEhEO11oRD9RYlUTKAwBAarckEiM41nw=;
        b=PbimUdfX/F6TFs13YshISHwytbIW5PLHM/UOpNV0nXsbEN0p5t6O288Q4toq/K4pTC
         DPa0ziEvmVpSIbekxaYO9VeI0A9ZLQvUhutVN6oSGFRKZ4oujHdXgF9q2Nco6jEH6853
         6KBBy93zeBOnYOGA4fW6An1HVBGOrZHXSXOqmpWG2MVo7UPoSIB9CVkfN7EuMPtS9Ouy
         d70Ggrem30La1ZHaD7umS02Zrg2O4INfI/g0CyxEz5tvdyeR6Uoe2oOVIhhDajdxlZ4Z
         1vfUEE/X2+yrldYWJFWriwFCkUdIXjN82nQnOMpIy7Y/tYTeCtc/xY9PWB0SzdKgQhPz
         LpjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vRYnLpjC;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x1S+n/33YBtoEhEO11oRD9RYlUTKAwBAarckEiM41nw=;
        b=Mb2YAufrbb/+1I/w5IuBcvDz++qlDXo77BBhcl/cGml8NamtwQd1t3h8KBIs4P+Z8Z
         KgU/xVS0FhpVesXwRXSTgi/YmgO4pIxXzZrLHsULW2+4zBtCUdoC6TAP6zkKYYRcUPzq
         iTexTcojLSxeryP7GqPZM7lq0MpCqbWu/RagumTz66pMf4wVYqNFZPIMCYItCjIkDrgT
         o2F2fOU/tzMnLgGd9egGz9+nXyvSL3zT2wVDQVWMLRsbgkUw5VhXgtBlL2nODGB7q2ch
         pw1bPYKCQ8myNkRV2FQbeHnIZS04D3ElQIdg/rvtD9hqDvi+pDKUCjEs1wm5bv8BhsGj
         DfLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x1S+n/33YBtoEhEO11oRD9RYlUTKAwBAarckEiM41nw=;
        b=tRPfVLzhebKoNnEA4dwnR/9Wg4VJh+dFF/QChpLyM+EBQmH69PraezNTpkXRqf4/+D
         TemQYksp5awMGFZuW1btRQKehNecaUUQ7+RnWSPTt4+Ne7Qab2umNydGpMbE6nvC94AH
         zZvMjrPaN7O3yq+uM2PYyygpTdMRKhLsWNxT7FtKO08YBEWQfq+cjlfc6KspwnoqH0bU
         5qKyFGN+BTXRlSmqd8sowvAQ5k6zEYQvVKBSL2BqCPokAZr+pr53XbfWx3hcQviA5M3b
         BY5Au6cr6SpwrqFzVYqMppUo44mWT81TeJsnLqNZ4EE07JuDvnnn65WN/+IB7I1NBhPR
         9ceg==
X-Gm-Message-State: AOAM532AfrQUj7Dn+MW7Ml4FWQKdkmEZQZvCgRG8VjpLQeOUyt+c+zHa
	GCes8PT0IrmEquNr3ucBiWo=
X-Google-Smtp-Source: ABdhPJwl1X6AliRKmxSde/DCqY9F6EjX8J+FB/faxSAz/9Ryijw3xZ1OAqN00TGUoQLOo8OU3o87Sg==
X-Received: by 2002:a25:8006:: with SMTP id m6mr24195314ybk.57.1605611405591;
        Tue, 17 Nov 2020 03:10:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2d56:: with SMTP id s22ls8480478ybe.0.gmail; Tue, 17 Nov
 2020 03:10:05 -0800 (PST)
X-Received: by 2002:a25:2304:: with SMTP id j4mr29706434ybj.348.1605611405064;
        Tue, 17 Nov 2020 03:10:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605611405; cv=none;
        d=google.com; s=arc-20160816;
        b=KveQdXEudu8QGNxMSAVxcEYS6dPHxyOEATaBPWN/Fk3X+lI9Vz+64BSwieIgwtzZb9
         lUeHUkzx108FWbaMkq8Kond+HpbYUgUjF4hLysZo0ZvYWUYoaM9oWxCKHDXs5Ik/kFAj
         VAU1iDmjZ2x5vVxpiSmw0kNqdYO4gdFGNSr2ANLKmjcCkQJvp+vNc3xD5QcMUJQfTDif
         p+6LbJG8/1ZW9FFNb3TYpI1nuRvNrCq/Tb7RMZ/ipgZ5KHEVZBdATw1KqoZYCvFtCre4
         3G1huzRFGZAjVyuQNk6iJxNPO7ZT+mU533+lAwC97XVTI+aiplNJzHVgqbHgqh3E0UPZ
         9bPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0kLaQ1Zmb/ABOcdrLOBhl1Qr/V76Xuf3esMliWy7s4A=;
        b=N5nXDDy4RkgrovnS+RLZk0iK82pim7sqw7ttsZ9/QoYUCp6QAv8ScEqzfWOmMsJmDl
         Em/+CQqKeT60PhuiAUpc1uVh5SzaPXDxZ3Qe620LEuK+wrEUIj6LtSuiNC5l9xNRLiPV
         y0tvF3ncJjD+3dJQK93qYseVCThRw6JHxSK13K3sF7TMXo9kBpefdzaKqJl3xVzNwqog
         AqMoB+GbovEqXGh1vyWpLCi6Sr6amns6dEcH0Qm8hdQdsex33K4M2JFncxu5UsA13MMq
         Whk+xBnj7+ae139sC0bNWfRCA70Sljjw/OhzAkHIUnDDz4H6pIKJchivA7ZMOTXpC52H
         rXfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vRYnLpjC;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id m3si377274ybf.1.2020.11.17.03.10.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Nov 2020 03:10:05 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id n132so19949403qke.1
        for <kasan-dev@googlegroups.com>; Tue, 17 Nov 2020 03:10:05 -0800 (PST)
X-Received: by 2002:a37:7b44:: with SMTP id w65mr19513059qkc.350.1605611404314;
 Tue, 17 Nov 2020 03:10:04 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com> <deb1af093f19c8848346682245513af059626412.1605305978.git.andreyknvl@google.com>
 <20201116151501.GC1357314@elver.google.com>
In-Reply-To: <20201116151501.GC1357314@elver.google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 17 Nov 2020 12:09:52 +0100
Message-ID: <CACT4Y+afJmb2YPVOyBtsEC1fd_jqgnrz5h9841Ko62Cumkyw9w@mail.gmail.com>
Subject: Re: [PATCH mm v3 11/19] kasan: add and integrate kasan boot parameters
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vRYnLpjC;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744
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

On Mon, Nov 16, 2020 at 4:15 PM Marco Elver <elver@google.com> wrote:
>
> On Fri, Nov 13, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> > Hardware tag-based KASAN mode is intended to eventually be used in
> > production as a security mitigation. Therefore there's a need for finer
> > control over KASAN features and for an existence of a kill switch.
> >
> > This change adds a few boot parameters for hardware tag-based KASAN that
> > allow to disable or otherwise control particular KASAN features.
> >
> > The features that can be controlled are:
> >
> > 1. Whether KASAN is enabled at all.
> > 2. Whether KASAN collects and saves alloc/free stacks.
> > 3. Whether KASAN panics on a detected bug or not.
> >
> > With this change a new boot parameter kasan.mode allows to choose one of
> > three main modes:
> >
> > - kasan.mode=off - KASAN is disabled, no tag checks are performed
> > - kasan.mode=prod - only essential production features are enabled
> > - kasan.mode=full - all KASAN features are enabled
> >
> > The chosen mode provides default control values for the features mentioned
> > above. However it's also possible to override the default values by
> > providing:
> >
> > - kasan.stacktrace=off/on - enable alloc/free stack collection
> >                             (default: on for mode=full, otherwise off)
> > - kasan.fault=report/panic - only report tag fault or also panic
> >                              (default: report)
> >
> > If kasan.mode parameter is not provided, it defaults to full when
> > CONFIG_DEBUG_KERNEL is enabled, and to prod otherwise.
> >
> > It is essential that switching between these modes doesn't require
> > rebuilding the kernel with different configs, as this is required by
> > the Android GKI (Generic Kernel Image) initiative [1].
> >
> > [1] https://source.android.com/devices/architecture/kernel/generic-kernel-image
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/If7d37003875b2ed3e0935702c8015c223d6416a4
>
> Reviewed-by: Marco Elver <elver@google.com>

Much nicer with the wrappers now.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> > ---
> >  mm/kasan/common.c  |  22 +++++--
> >  mm/kasan/hw_tags.c | 151 +++++++++++++++++++++++++++++++++++++++++++++
> >  mm/kasan/kasan.h   |  16 +++++
> >  mm/kasan/report.c  |  14 ++++-
> >  4 files changed, 196 insertions(+), 7 deletions(-)
> >
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 1ac4f435c679..a11e3e75eb08 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -135,6 +135,11 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> >       unsigned int redzone_size;
> >       int redzone_adjust;
> >
> > +     if (!kasan_stack_collection_enabled()) {
> > +             *flags |= SLAB_KASAN;
> > +             return;
> > +     }
> > +
> >       /* Add alloc meta. */
> >       cache->kasan_info.alloc_meta_offset = *size;
> >       *size += sizeof(struct kasan_alloc_meta);
> > @@ -171,6 +176,8 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> >
> >  size_t kasan_metadata_size(struct kmem_cache *cache)
> >  {
> > +     if (!kasan_stack_collection_enabled())
> > +             return 0;
> >       return (cache->kasan_info.alloc_meta_offset ?
> >               sizeof(struct kasan_alloc_meta) : 0) +
> >               (cache->kasan_info.free_meta_offset ?
> > @@ -263,11 +270,13 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
> >  {
> >       struct kasan_alloc_meta *alloc_meta;
> >
> > -     if (!(cache->flags & SLAB_KASAN))
> > -             return (void *)object;
> > +     if (kasan_stack_collection_enabled()) {
> > +             if (!(cache->flags & SLAB_KASAN))
> > +                     return (void *)object;
> >
> > -     alloc_meta = kasan_get_alloc_meta(cache, object);
> > -     __memset(alloc_meta, 0, sizeof(*alloc_meta));
> > +             alloc_meta = kasan_get_alloc_meta(cache, object);
> > +             __memset(alloc_meta, 0, sizeof(*alloc_meta));
> > +     }
> >
> >       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
> >               object = set_tag(object, assign_tag(cache, object, true, false));
> > @@ -307,6 +316,9 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> >       rounded_up_size = round_up(cache->object_size, KASAN_GRANULE_SIZE);
> >       poison_range(object, rounded_up_size, KASAN_KMALLOC_FREE);
> >
> > +     if (!kasan_stack_collection_enabled())
> > +             return false;
> > +
> >       if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
> >                       unlikely(!(cache->flags & SLAB_KASAN)))
> >               return false;
> > @@ -357,7 +369,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
> >       poison_range((void *)redzone_start, redzone_end - redzone_start,
> >                    KASAN_KMALLOC_REDZONE);
> >
> > -     if (cache->flags & SLAB_KASAN)
> > +     if (kasan_stack_collection_enabled() && (cache->flags & SLAB_KASAN))
> >               set_alloc_info(cache, (void *)object, flags);
> >
> >       return set_tag(object, tag);
> > diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> > index 863fed4edd3f..30ce88935e9d 100644
> > --- a/mm/kasan/hw_tags.c
> > +++ b/mm/kasan/hw_tags.c
> > @@ -8,18 +8,115 @@
> >
> >  #define pr_fmt(fmt) "kasan: " fmt
> >
> > +#include <linux/init.h>
> >  #include <linux/kasan.h>
> >  #include <linux/kernel.h>
> >  #include <linux/memory.h>
> >  #include <linux/mm.h>
> > +#include <linux/static_key.h>
> >  #include <linux/string.h>
> >  #include <linux/types.h>
> >
> >  #include "kasan.h"
> >
> > +enum kasan_arg_mode {
> > +     KASAN_ARG_MODE_DEFAULT,
> > +     KASAN_ARG_MODE_OFF,
> > +     KASAN_ARG_MODE_PROD,
> > +     KASAN_ARG_MODE_FULL,
> > +};
> > +
> > +enum kasan_arg_stacktrace {
> > +     KASAN_ARG_STACKTRACE_DEFAULT,
> > +     KASAN_ARG_STACKTRACE_OFF,
> > +     KASAN_ARG_STACKTRACE_ON,
> > +};
> > +
> > +enum kasan_arg_fault {
> > +     KASAN_ARG_FAULT_DEFAULT,
> > +     KASAN_ARG_FAULT_REPORT,
> > +     KASAN_ARG_FAULT_PANIC,
> > +};
> > +
> > +static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
> > +static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
> > +static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
> > +
> > +/* Whether KASAN is enabled at all. */
> > +DEFINE_STATIC_KEY_FALSE_RO(kasan_flag_enabled);
> > +EXPORT_SYMBOL(kasan_flag_enabled);
> > +
> > +/* Whether to collect alloc/free stack traces. */
> > +DEFINE_STATIC_KEY_FALSE_RO(kasan_flag_stacktrace);
> > +
> > +/* Whether panic or disable tag checking on fault. */
> > +bool kasan_flag_panic __ro_after_init;
> > +
> > +/* kasan.mode=off/prod/full */
> > +static int __init early_kasan_mode(char *arg)
> > +{
> > +     if (!arg)
> > +             return -EINVAL;
> > +
> > +     if (!strcmp(arg, "off"))
> > +             kasan_arg_mode = KASAN_ARG_MODE_OFF;
> > +     else if (!strcmp(arg, "prod"))
> > +             kasan_arg_mode = KASAN_ARG_MODE_PROD;
> > +     else if (!strcmp(arg, "full"))
> > +             kasan_arg_mode = KASAN_ARG_MODE_FULL;
> > +     else
> > +             return -EINVAL;
> > +
> > +     return 0;
> > +}
> > +early_param("kasan.mode", early_kasan_mode);
> > +
> > +/* kasan.stack=off/on */
> > +static int __init early_kasan_flag_stacktrace(char *arg)
> > +{
> > +     if (!arg)
> > +             return -EINVAL;
> > +
> > +     if (!strcmp(arg, "off"))
> > +             kasan_arg_stacktrace = KASAN_ARG_STACKTRACE_OFF;
> > +     else if (!strcmp(arg, "on"))
> > +             kasan_arg_stacktrace = KASAN_ARG_STACKTRACE_ON;
> > +     else
> > +             return -EINVAL;
> > +
> > +     return 0;
> > +}
> > +early_param("kasan.stacktrace", early_kasan_flag_stacktrace);
> > +
> > +/* kasan.fault=report/panic */
> > +static int __init early_kasan_fault(char *arg)
> > +{
> > +     if (!arg)
> > +             return -EINVAL;
> > +
> > +     if (!strcmp(arg, "report"))
> > +             kasan_arg_fault = KASAN_ARG_FAULT_REPORT;
> > +     else if (!strcmp(arg, "panic"))
> > +             kasan_arg_fault = KASAN_ARG_FAULT_PANIC;
> > +     else
> > +             return -EINVAL;
> > +
> > +     return 0;
> > +}
> > +early_param("kasan.fault", early_kasan_fault);
> > +
> >  /* kasan_init_hw_tags_cpu() is called for each CPU. */
> >  void kasan_init_hw_tags_cpu(void)
> >  {
> > +     /*
> > +      * There's no need to check that the hardware is MTE-capable here,
> > +      * as this function is only called for MTE-capable hardware.
> > +      */
> > +
> > +     /* If KASAN is disabled, do nothing. */
> > +     if (kasan_arg_mode == KASAN_ARG_MODE_OFF)
> > +             return;
> > +
> >       hw_init_tags(KASAN_TAG_MAX);
> >       hw_enable_tagging();
> >  }
> > @@ -27,6 +124,60 @@ void kasan_init_hw_tags_cpu(void)
> >  /* kasan_init_hw_tags() is called once on boot CPU. */
> >  void __init kasan_init_hw_tags(void)
> >  {
> > +     /* If hardware doesn't support MTE, do nothing. */
> > +     if (!system_supports_mte())
> > +             return;
> > +
> > +     /* Choose KASAN mode if kasan boot parameter is not provided. */
> > +     if (kasan_arg_mode == KASAN_ARG_MODE_DEFAULT) {
> > +             if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
> > +                     kasan_arg_mode = KASAN_ARG_MODE_FULL;
> > +             else
> > +                     kasan_arg_mode = KASAN_ARG_MODE_PROD;
> > +     }
> > +
> > +     /* Preset parameter values based on the mode. */
> > +     switch (kasan_arg_mode) {
> > +     case KASAN_ARG_MODE_DEFAULT:
> > +             /* Shouldn't happen as per the check above. */
> > +             WARN_ON(1);
> > +             return;
> > +     case KASAN_ARG_MODE_OFF:
> > +             /* If KASAN is disabled, do nothing. */
> > +             return;
> > +     case KASAN_ARG_MODE_PROD:
> > +             static_branch_enable(&kasan_flag_enabled);
> > +             break;
> > +     case KASAN_ARG_MODE_FULL:
> > +             static_branch_enable(&kasan_flag_enabled);
> > +             static_branch_enable(&kasan_flag_stacktrace);
> > +             break;
> > +     }
> > +
> > +     /* Now, optionally override the presets. */
> > +
> > +     switch (kasan_arg_stacktrace) {
> > +     case KASAN_ARG_STACKTRACE_DEFAULT:
> > +             break;
> > +     case KASAN_ARG_STACKTRACE_OFF:
> > +             static_branch_disable(&kasan_flag_stacktrace);
> > +             break;
> > +     case KASAN_ARG_STACKTRACE_ON:
> > +             static_branch_enable(&kasan_flag_stacktrace);
> > +             break;
> > +     }
> > +
> > +     switch (kasan_arg_fault) {
> > +     case KASAN_ARG_FAULT_DEFAULT:
> > +             break;
> > +     case KASAN_ARG_FAULT_REPORT:
> > +             kasan_flag_panic = false;
> > +             break;
> > +     case KASAN_ARG_FAULT_PANIC:
> > +             kasan_flag_panic = true;
> > +             break;
> > +     }
> > +
> >       pr_info("KernelAddressSanitizer initialized\n");
> >  }
> >
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index 8aa83b7ad79e..d01a5ac34f70 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -6,6 +6,22 @@
> >  #include <linux/kfence.h>
> >  #include <linux/stackdepot.h>
> >
> > +#ifdef CONFIG_KASAN_HW_TAGS
> > +#include <linux/static_key.h>
> > +DECLARE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
> > +static inline bool kasan_stack_collection_enabled(void)
> > +{
> > +     return static_branch_unlikely(&kasan_flag_stacktrace);
> > +}
> > +#else
> > +static inline bool kasan_stack_collection_enabled(void)
> > +{
> > +     return true;
> > +}
> > +#endif
> > +
> > +extern bool kasan_flag_panic __ro_after_init;
> > +
> >  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> >  #define KASAN_GRANULE_SIZE   (1UL << KASAN_SHADOW_SCALE_SHIFT)
> >  #else
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 76a0e3ae2049..ffa6076b1710 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -99,6 +99,10 @@ static void end_report(unsigned long *flags)
> >               panic_on_warn = 0;
> >               panic("panic_on_warn set ...\n");
> >       }
> > +#ifdef CONFIG_KASAN_HW_TAGS
> > +     if (kasan_flag_panic)
> > +             panic("kasan.fault=panic set ...\n");
> > +#endif
> >       kasan_enable_current();
> >  }
> >
> > @@ -161,8 +165,8 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
> >               (void *)(object_addr + cache->object_size));
> >  }
> >
> > -static void describe_object(struct kmem_cache *cache, void *object,
> > -                             const void *addr, u8 tag)
> > +static void describe_object_stacks(struct kmem_cache *cache, void *object,
> > +                                     const void *addr, u8 tag)
> >  {
> >       struct kasan_alloc_meta *alloc_meta = kasan_get_alloc_meta(cache, object);
> >
> > @@ -190,7 +194,13 @@ static void describe_object(struct kmem_cache *cache, void *object,
> >               }
> >  #endif
> >       }
> > +}
> >
> > +static void describe_object(struct kmem_cache *cache, void *object,
> > +                             const void *addr, u8 tag)
> > +{
> > +     if (kasan_stack_collection_enabled())
> > +             describe_object_stacks(cache, object, addr, tag);
> >       describe_object_addr(cache, object, addr);
> >  }
> >
> > --
> > 2.29.2.299.gdc1121823c-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BafJmb2YPVOyBtsEC1fd_jqgnrz5h9841Ko62Cumkyw9w%40mail.gmail.com.
