Return-Path: <kasan-dev+bncBCMIZB7QWENRBA6DZSVAMGQEV6WZQTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 042DC7EAAE3
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 08:28:05 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2c59a4dcdd0sf48220441fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 23:28:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699946884; cv=pass;
        d=google.com; s=arc-20160816;
        b=lpkE0FPl2zkY7pJWshnrU44GYQx5yJ+LLq/TcMwi231Rde2kefEpU/A09hdKtRfA6i
         OjyDnT7qeQv05mmUL9j6GdkcEpl352PPijpemnKQ0MTZawi80S6iPLJE2ihACi6Xvo/d
         K+DjbHdNc6n3DbmY+RMPelJ1MI41BQg3eEfyfuodF0EJgYFXRut/Kuxi6JtPohQcwiHs
         SZhePIu+NQJjSN00sGDkhxv2WVvvojUeoPuOZVB5BaFdye+u0j6TN3U6kd6JDx4mEJTB
         dkpreALN8dsICJD6aYYT6CxwcL/JGyd3FuP+lXu4Mf/s0PxN7+uNhcxnXUx4tz67tdM5
         TlBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1NCSJ+SeQJ0vFsH9bd8a0BZO9q22HKYSQSv+7VYofjo=;
        fh=Cxdz3lXx9q85yacnGVuiIilAYWk/9KO8DtHEl0n0w48=;
        b=vxQykTyhPu2RjF9ftsTLceTlhIgjUBAN2hoHchd9xgOwSBIxUBp/qPVAhD5NtPvu+x
         DUJi28nt+nZFs2rrMMv1l4onXhGy7X8Qr55G2I9jSLnf76INNiaBpEuMdvlL38N0BVy4
         4q8iX+d8rpjk+bCOWk9g4SHHW/wRrjuutjI69p+3nRenPrmB7IZ/BwFm8jNbbpSR/A2S
         mKWRMKZjTkum1GtkSXznfXllsVffbUbD3ocCbAlRau3nnREGABLpSPr/aJs3SMkPjNpT
         1aHHUnU8vZSzVwOXDNIowTMTHr/Hri6TpjrfSM9IorRg3aV4wci8c+d2GTXU0Nj0wSq0
         N0DA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="l/WlBsEY";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699946884; x=1700551684; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1NCSJ+SeQJ0vFsH9bd8a0BZO9q22HKYSQSv+7VYofjo=;
        b=W2eswRM8GUgpO6V9Qa4dHA/VnihER8y/6ebcoXgHKTNZi7xROfeBnMx+WKFoo4TVgB
         nmBnOTPuK9pl/Vp7vc8zdONv9eBWhiWQMAELLlm+A43AvP25cmDmSE2QHU1L9cdpKvRn
         d4oGv0EUOgpkYRkWW3Q643KltyiuFT8pE1gDSDZu5sPEXISGbY+cu+Sh7y2v12eLVfiW
         zv2YmDPGjZXSP/WDtP3aWv4VWlvH4vNN3t5Bt/v7I1JJfY27AKJvjHZVtmPrFdL6/eXw
         61AAGlcig/L1wlcNYq2Vn4yztmisXg3qEfBGATjUo9Nx6N2NROoJVeqxofDb1w1VWfi3
         u6Aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699946884; x=1700551684;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1NCSJ+SeQJ0vFsH9bd8a0BZO9q22HKYSQSv+7VYofjo=;
        b=HOplgqAAzu9yZyw/EyDqqDyNaTxZw5onP/oupq8BFnBr+3jLlXoLZaWJw02MsqIUxA
         b5GbvzUKRX85onPx7uf51H5x0Umg8ZHwoTry4mNimDQVy6hurrGbn1CMzPBVZ3e0oHNy
         1F96nUnoMO0vDzO35969eg4bS74xr1Eek+G1maXsvsFw//YJz6y+JVjgweJbeR+Z8c/1
         j8eGBQFo602grl0Su3qu+pdyertHAbPLs1+9/ZMZiwvTbiPAl6zYfKs4yGIHK2rL+9MG
         SlnLgZ9IJAtuGwi5I7OY0k/bzH49HcETQjLwO1whDpfZiq5FKWauFEYdu3a+iuv+kdpu
         FUVg==
X-Gm-Message-State: AOJu0Yw6RphZgWi996ehB5cHlw1rksOTdckRmVtoal+cKfDrImuYPl7z
	qAwy1Y/1NzhbwMH8BlynQxk=
X-Google-Smtp-Source: AGHT+IExLvz+HpL1O1+9HXsZF92DAstZvJkWK96MweW+JpNwg9Eb21UGMaC2u1kpH7cgxHnaC1CuWA==
X-Received: by 2002:a05:651c:2c8:b0:2c7:fa6:718c with SMTP id f8-20020a05651c02c800b002c70fa6718cmr1047400ljo.9.1699946883880;
        Mon, 13 Nov 2023 23:28:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b52a:0:b0:2b9:631f:ac29 with SMTP id z10-20020a2eb52a000000b002b9631fac29ls492583ljm.1.-pod-prod-08-eu;
 Mon, 13 Nov 2023 23:28:02 -0800 (PST)
X-Received: by 2002:a2e:7319:0:b0:2bf:f989:b8e5 with SMTP id o25-20020a2e7319000000b002bff989b8e5mr1058898ljc.33.1699946881678;
        Mon, 13 Nov 2023 23:28:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699946881; cv=none;
        d=google.com; s=arc-20160816;
        b=vgLj5ofQAOiptakv9rtC0yII4VrJ3eZIZYXcj4zB3nxnOC9ZDklUBlGMq2d4OMxr+k
         pTUN8ZCqbufdcSg7UhrCuG/Das1ruC3s6Ol8qvhA+9VK47gVQD8LEszahGQyt2+RvZ0U
         ZLftd2VUHRc1DlBbeetDFTtBJ8p0I92zpZkWVptCxNWbVU7oTjUyU6vqbnkHqSFwcBHu
         7Z4GRAx940Wxh3FDcFOqyQdwriIV9UwEl9rboJVXElXqVjCvFCDmGfitEIKgEGPk8GzA
         2PVDZxdOqK0QEE04Mnuu9aCLkO4KVdOPVg8lhD0jWcbmqtMzRBbjlyo3thOLMIkbdJwu
         0JTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=j7k5QLsXr1VaePKPJwpckb69EbdmzQCB0DATBTJO1Js=;
        fh=Cxdz3lXx9q85yacnGVuiIilAYWk/9KO8DtHEl0n0w48=;
        b=PVI1Awm5GZ8UMShcoewoawaGi/dqEZ6YxypDGpWC9L4+h4BvYtZbeJuNjtJ8L5Vctv
         rZFgfHoiUBds0UlIqOOzyUsYijzhK3vkmpnjXQ5Ve/YgRBgeJRRTVO3lqrBOy+XrwObK
         l2rnRIWGn26Gg0e9UDgKNm7LMDGHO4TmcvQIF9Mt79koVboGgtDwAdgVJUCH35vtuLrw
         WU8/Zu/ap8Wv6RKWhJpYR5ay/Nr9NqJWrVZihXbcOGrMTVcKZ2YszPat7ABUfzyJgU50
         lomfVIie0QqYrcUVyHs1WwjBcFMnetgQ/yL/3gdeOufLFOTbDEm1GiBz0SP+uSFKaQyA
         084Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="l/WlBsEY";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x52c.google.com (mail-ed1-x52c.google.com. [2a00:1450:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id t26-20020a2e781a000000b002c12145a0cbsi260433ljc.7.2023.11.13.23.28.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Nov 2023 23:28:01 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::52c as permitted sender) client-ip=2a00:1450:4864:20::52c;
Received: by mail-ed1-x52c.google.com with SMTP id 4fb4d7f45d1cf-54366bb1c02so6145a12.1
        for <kasan-dev@googlegroups.com>; Mon, 13 Nov 2023 23:28:01 -0800 (PST)
X-Received: by 2002:aa7:dc0f:0:b0:545:94c:862e with SMTP id
 b15-20020aa7dc0f000000b00545094c862emr93008edu.2.1699946880793; Mon, 13 Nov
 2023 23:28:00 -0800 (PST)
MIME-Version: 1.0
References: <VI1P193MB0752058FAECD2AC1E5E68D7399B3A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
In-Reply-To: <VI1P193MB0752058FAECD2AC1E5E68D7399B3A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 14 Nov 2023 08:27:44 +0100
Message-ID: <CACT4Y+Ya4yTvAmaELJN5st3GJYo1KKzC9qw9sdD0g3jb48O7tg@mail.gmail.com>
Subject: Re: [RFC PATCH] kasan: Record and report more information
To: Juntong Deng <juntong.deng@outlook.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-kernel-mentees@lists.linuxfoundation.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="l/WlBsEY";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::52c
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

On Mon, 13 Nov 2023 at 22:17, Juntong Deng <juntong.deng@outlook.com> wrote:
>
> Record and report more information to help us find the cause of
> the bug (for example, bugs caused by subtle race condition).
>
> This patch adds recording and showing CPU number and timestamp at
> allocation and free (controlled by CONFIG_KASAN_EXTRA_INFO), and
> adds recording and showing timestamp at error occurrence (CPU number
> is already shown by dump_stack_lvl). The timestamps in the report use
> the same format and source as printk.
>
> In order to record CPU number and timestamp at allocation and free,
> corresponding members need to be added to the relevant data structures,
> which may lead to increased memory consumption.
>
> In Generic KASAN, members are added to struct kasan_track. Since in
> most cases, alloc meta is stored in the redzone and free meta is
> stored in the object or the redzone, memory consumption will not
> increase much.
>
> In SW_TAGS KASAN and HW_TAGS KASAN, members are added to
> struct kasan_stack_ring_entry. Memory consumption increases as the
> size of struct kasan_stack_ring_entry increases (this part of the
> memory is allocated by memblock), but since this is configurable,
> it is up to the user to choose.
>
> Signed-off-by: Juntong Deng <juntong.deng@outlook.com>
> ---
>  lib/Kconfig.kasan      | 11 +++++++++++
>  mm/kasan/common.c      |  5 +++++
>  mm/kasan/kasan.h       |  9 +++++++++
>  mm/kasan/report.c      | 28 ++++++++++++++++++++++------
>  mm/kasan/report_tags.c | 18 ++++++++++++++++++
>  mm/kasan/tags.c        | 15 +++++++++++++++
>  6 files changed, 80 insertions(+), 6 deletions(-)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index fdca89c05745..d9611564b339 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -207,4 +207,15 @@ config KASAN_MODULE_TEST
>           A part of the KASAN test suite that is not integrated with KUnit.
>           Incompatible with Hardware Tag-Based KASAN.
>
> +config KASAN_EXTRA_INFO
> +       bool "Record and report more information"
> +       depends on KASAN
> +       help
> +         Record and report more information to help us find the cause of
> +         the bug. The trade-off is potentially increased memory consumption
> +         (to record more information).
> +
> +         Currently the CPU number and timestamp are additionally recorded
> +         at allocation and free.

Hi Juntong,

Thanks for working on this.

As a KASAN developer I understand what this is doing, but I am trying
to think from a position of a user that does not know details of KASAN
implementation. From this position it may be useful to say somewhere
that information is recorded "per heap allocation". Perhaps something
like:

"Currently the CPU number and timestamp are additionally recorded for
each heap block at allocation and free time".

Also it's unclear what the memory consumption increase is. You say
"potentially|, so may it not increase at all? If it increases, by how
much? I obviously want more information, if I can afford it, but I
can't understand if I can or not based on this description. I would
assume that this may be a problem only for small/embedded devices.
Can we provide some ballpark estimation of the memory consumption
increase? And somehow say that's probably not an issue for larger
machines?




>  endif # KASAN
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 256930da578a..7a81566d9d66 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -20,6 +20,7 @@
>  #include <linux/module.h>
>  #include <linux/printk.h>
>  #include <linux/sched.h>
> +#include <linux/sched/clock.h>
>  #include <linux/sched/task_stack.h>
>  #include <linux/slab.h>
>  #include <linux/stacktrace.h>
> @@ -50,6 +51,10 @@ void kasan_set_track(struct kasan_track *track, gfp_t flags)
>  {
>         track->pid = current->pid;
>         track->stack = kasan_save_stack(flags, true);
> +#ifdef CONFIG_KASAN_EXTRA_INFO
> +       track->cpu = raw_smp_processor_id();
> +       track->ts_nsec = local_clock();

What does "local_" mean? Is this clock value comparable across CPUs?


> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>  }
>
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 8b06bab5c406..b3899a255aca 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -187,6 +187,10 @@ static inline bool kasan_requires_meta(void)
>  struct kasan_track {
>         u32 pid;
>         depot_stack_handle_t stack;
> +#ifdef CONFIG_KASAN_EXTRA_INFO
> +       u32 cpu;
> +       u64 ts_nsec;

This increases the size of meta from 8 to 24 bytes.
Can we somehow store the timestamp as 32 bits? Maybe compress the CPU
number (it shouldn't be larger than 20 bits?)?
I see below we report on microseconds, so we don't low bits of the
timestamp as well.


I see there is a deficiency in kasan_cache_create():
https://elixir.bootlin.com/linux/latest/source/mm/kasan/generic.c#L412

If free_meta does not fit into the object, we add it after the object.
But we could overlap it with the object.
For example if the object size is 16 bytes and free_meta size is 24
bytes, we could increase object size to 24, while currently we
increase it to 16+24 = 40.
We need to place it after the object only if we have these other cases
"(cache->flags & SLAB_TYPESAFE_BY_RCU) || cache->ctor".

Currently it affects only kmalloc-8 slab.
But with this change it will affect at least kmalloc-16 slab as well.




> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>  };
>
>  enum kasan_report_type {
> @@ -202,6 +206,7 @@ struct kasan_report_info {
>         size_t access_size;
>         bool is_write;
>         unsigned long ip;
> +       u64 ts_nsec;
>
>         /* Filled in by the common reporting code. */
>         const void *first_bad_addr;
> @@ -278,6 +283,10 @@ struct kasan_stack_ring_entry {
>         u32 pid;
>         depot_stack_handle_t stack;
>         bool is_free;
> +#ifdef CONFIG_KASAN_EXTRA_INFO
> +       u32 cpu;
> +       u64 ts_nsec;
> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>  };
>
>  struct kasan_stack_ring {
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index e77facb62900..b6feaf807c08 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -25,6 +25,7 @@
>  #include <linux/types.h>
>  #include <linux/kasan.h>
>  #include <linux/module.h>
> +#include <linux/sched/clock.h>
>  #include <linux/sched/task_stack.h>
>  #include <linux/uaccess.h>
>  #include <trace/events/error_report.h>
> @@ -242,27 +243,40 @@ static void end_report(unsigned long *flags, const void *addr, bool is_write)
>
>  static void print_error_description(struct kasan_report_info *info)
>  {
> +       unsigned long rem_usec = do_div(info->ts_nsec, NSEC_PER_SEC) / 1000;
> +
>         pr_err("BUG: KASAN: %s in %pS\n", info->bug_type, (void *)info->ip);
>
>         if (info->type != KASAN_REPORT_ACCESS) {
> -               pr_err("Free of addr %px by task %s/%d\n",
> -                       info->access_addr, current->comm, task_pid_nr(current));
> +               pr_err("Free of addr %px by task %s/%d at %lu.%06lus\n",
> +                       info->access_addr, current->comm, task_pid_nr(current),
> +                       (unsigned long)info->ts_nsec, rem_usec);
>                 return;
>         }
>
>         if (info->access_size)
> -               pr_err("%s of size %zu at addr %px by task %s/%d\n",
> +               pr_err("%s of size %zu at addr %px by task %s/%d at %lu.%06lus\n",
>                         info->is_write ? "Write" : "Read", info->access_size,
> -                       info->access_addr, current->comm, task_pid_nr(current));
> +                       info->access_addr, current->comm, task_pid_nr(current),
> +                       (unsigned long)info->ts_nsec, rem_usec);
>         else
> -               pr_err("%s at addr %px by task %s/%d\n",
> +               pr_err("%s at addr %px by task %s/%d at %lu.%06lus\n",
>                         info->is_write ? "Write" : "Read",
> -                       info->access_addr, current->comm, task_pid_nr(current));
> +                       info->access_addr, current->comm, task_pid_nr(current),
> +                       (unsigned long)info->ts_nsec, rem_usec);
>  }
>
>  static void print_track(struct kasan_track *track, const char *prefix)
>  {
> +#ifdef CONFIG_KASAN_EXTRA_INFO
> +       unsigned long rem_usec = do_div(track->ts_nsec, NSEC_PER_SEC) / 1000;
> +
> +       pr_err("%s by task %u on cpu %d at %lu.%06lus:\n",
> +                       prefix, track->pid, track->cpu,
> +                       (unsigned long)track->ts_nsec, rem_usec);
> +#else
>         pr_err("%s by task %u:\n", prefix, track->pid);
> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>         if (track->stack)
>                 stack_depot_print(track->stack);
>         else
> @@ -544,6 +558,7 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_ty
>         info.access_size = 0;
>         info.is_write = false;
>         info.ip = ip;
> +       info.ts_nsec = local_clock();
>
>         complete_report_info(&info);
>
> @@ -582,6 +597,7 @@ bool kasan_report(const void *addr, size_t size, bool is_write,
>         info.access_size = size;
>         info.is_write = is_write;
>         info.ip = ip;
> +       info.ts_nsec = local_clock();
>
>         complete_report_info(&info);
>
> diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
> index 8b8bfdb3cfdb..4d62f1b3e11d 100644
> --- a/mm/kasan/report_tags.c
> +++ b/mm/kasan/report_tags.c
> @@ -26,6 +26,18 @@ static const char *get_common_bug_type(struct kasan_report_info *info)
>         return "invalid-access";
>  }
>
> +#ifdef CONFIG_KASAN_EXTRA_INFO
> +static void kasan_complete_extra_report_info(struct kasan_track *track,
> +                                        struct kasan_stack_ring_entry *entry)
> +{
> +       u32 cpu = READ_ONCE(entry->cpu);
> +       u64 ts_nsec = READ_ONCE(entry->ts_nsec);
> +
> +       track->cpu = cpu;
> +       track->ts_nsec = ts_nsec;
> +}
> +#endif /* CONFIG_KASAN_EXTRA_INFO */
> +
>  void kasan_complete_mode_report_info(struct kasan_report_info *info)
>  {
>         unsigned long flags;
> @@ -82,6 +94,9 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
>
>                         info->free_track.pid = pid;
>                         info->free_track.stack = stack;
> +#ifdef CONFIG_KASAN_EXTRA_INFO
> +                       kasan_complete_extra_report_info(&info->free_track, entry);
> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>                         free_found = true;
>
>                         /*
> @@ -97,6 +112,9 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
>
>                         info->alloc_track.pid = pid;
>                         info->alloc_track.stack = stack;
> +#ifdef CONFIG_KASAN_EXTRA_INFO
> +                       kasan_complete_extra_report_info(&info->alloc_track, entry);
> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>                         alloc_found = true;
>
>                         /*
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 7dcfe341d48e..474ce7e8be8b 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -13,6 +13,7 @@
>  #include <linux/memblock.h>
>  #include <linux/memory.h>
>  #include <linux/mm.h>
> +#include <linux/sched/clock.h>
>  #include <linux/static_key.h>
>  #include <linux/string.h>
>  #include <linux/types.h>
> @@ -92,6 +93,17 @@ void __init kasan_init_tags(void)
>         }
>  }
>
> +#ifdef CONFIG_KASAN_EXTRA_INFO
> +static void save_extra_info(struct kasan_stack_ring_entry *entry)
> +{
> +       u32 cpu = raw_smp_processor_id();
> +       u64 ts_nsec = local_clock();
> +
> +       WRITE_ONCE(entry->cpu, cpu);
> +       WRITE_ONCE(entry->ts_nsec, ts_nsec);
> +}
> +#endif /* CONFIG_KASAN_EXTRA_INFO */
> +
>  static void save_stack_info(struct kmem_cache *cache, void *object,
>                         gfp_t gfp_flags, bool is_free)
>  {
> @@ -124,6 +136,9 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
>         WRITE_ONCE(entry->pid, current->pid);
>         WRITE_ONCE(entry->stack, stack);
>         WRITE_ONCE(entry->is_free, is_free);
> +#ifdef CONFIG_KASAN_EXTRA_INFO
> +       save_extra_info(entry);
> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>
>         /*
>          * Paired with smp_load_acquire() in kasan_complete_mode_report_info().
> --
> 2.39.2
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYa4yTvAmaELJN5st3GJYo1KKzC9qw9sdD0g3jb48O7tg%40mail.gmail.com.
