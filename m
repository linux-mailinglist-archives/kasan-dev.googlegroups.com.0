Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3UNXSQAMGQEHB4OFMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id E403B6B75CF
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 12:20:15 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id z8-20020a92cd08000000b00317b27a795asf6317971iln.0
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 04:20:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678706414; cv=pass;
        d=google.com; s=arc-20160816;
        b=xgwsyihYpOJ7t4Hz7oSD8G+R0uaFgREFqSKSEjfpkwY52h8JDaxXJmc8Mylsu5n0DJ
         nsQB+VhVGyBmf1qPpY/HbhzW1AgEaK2HG4nTvMZs8BfLpYLuc3MrfhHIQj6UKW6cHYdc
         KZWEyVAmEUuN+/mwIwI3d/s46Ghm/PriAsLPZqaclL6gstbb75kblZC+MGYk9wWXzOdx
         GmqDN2NcQ7prdV8Ckf8BRSlECG0qaVMAZSg7+ECY8pZszobfyTyYFqG7DJE/zbLuai55
         HdbFwQsJoQ2q81ab8cxJUMmoakK2VK3vVfrQv3jsM9c8zDjR6hZnKaobdiWpZKLpBI+t
         n66g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=w4iW0AcQJxRg04ayQKZ3XqXv0/Q9X3D57lRBriuf24I=;
        b=ZvUfJUTRFm68zIDKuwtBX8lFUMN0/Kd+/mc03Na6i72nl+hXryWKgpNHix+lbIF9Pe
         P1BbUyCFY1MCnFGxzUBdTONUeYQt0NOtclZTnFAtNgOL/o2bmz5u3FnirbV3GYQboblt
         U31LIGwyQ81KudWx3+QlLZ9uwXjQJRi4fbBdFcJaEIG8MSSon1yOWoudCf7uNXzroNUn
         j+zz7td8joFUBg/D1EZMm9DeHEezPeEGT89DqD8rC+QZLkQSHjBDdHdu8GreFwARhrYB
         /Pj/L+xlmmoqMNAMsrzGKIOebxuRpMMCs5rCxDE+VfJqWVUWrgvoGGYloeqb9Wh7WCQr
         Ojgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dDpkCQjC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678706414;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=w4iW0AcQJxRg04ayQKZ3XqXv0/Q9X3D57lRBriuf24I=;
        b=n5bDbCY4AX7/KFrhXtFgIvmHMJ73m+5xO5gZRdCbOhTfYaKKrGMZvhrV4Gn5tjrZbW
         ROFERoZHiJUgR2E8OQfip2CZDRufTKHl0n2Qc5umY7/rGSgDAiG5R3o64pcsnpKrbQJb
         WK2JB2r/WHUnGpKgmnH67VjahZ9gWk0mvWT13VA039E4YGUuPWTrYPskGvJI5BDlUiIx
         y/UczChZsDf7UJBZQdB1pNjyHEDaonq9V9fwha8b/A9yo/763EgfjEkXNJQPNMfP+VCx
         eIvB4vr3x14XCm9WkDolECY8GBrhMdyH15pP8Tftp6jApweY9R7qSs71hACc3O8vuuRv
         mNRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678706414;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=w4iW0AcQJxRg04ayQKZ3XqXv0/Q9X3D57lRBriuf24I=;
        b=n7aDTXgLvD+sdF4K7WYJOr8dSrY6N0IFRcHDS75DYeUuIwjdrKnX3ulZ5qu2z/GMDE
         9r2LzigyvSNUQQMpFEwAi7RpZ+aKc9mc3TL8ulvaK0R3//JheGuzWi7qztdGvnN7aYLg
         OkHOKJuotSIPwWXDIDrBDdZPK+9sEfzNeojMKksZjrPP+RWu0PIm7SPsKPo9tOmIsqXe
         ECgTVkWMCgxZ/n3/BapEUAsRgQSSKmSnN6svPgVlvvpkvvKkK6pOQEAdpwvgmpKl37ut
         ETUNUCY0jD/63DBN9X8Il5quw5WSmF9t1xKHtl8jcJRccVLas5IJCa9Y68If+DrmYzkg
         8qCA==
X-Gm-Message-State: AO0yUKUg3brR2vI0BqJABsJ6cjomMGyV9EwUdvEYMjXvk5twHjq9lyhP
	XoXSHx9AiSTxPk4KpDDZNT4=
X-Google-Smtp-Source: AK7set8orJz04v2uzbWmgF4xMvOTb/ZuQsEhIOE+JCdeJ5S4n9UB6aDRTE1C6Yt57qxHYJ0+BTp5QQ==
X-Received: by 2002:a02:7310:0:b0:3a9:75c9:da25 with SMTP id y16-20020a027310000000b003a975c9da25mr16683482jab.1.1678706414436;
        Mon, 13 Mar 2023 04:20:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1045:b0:316:e54a:82ff with SMTP id
 p5-20020a056e02104500b00316e54a82ffls3739051ilj.10.-pod-prod-gmail; Mon, 13
 Mar 2023 04:20:13 -0700 (PDT)
X-Received: by 2002:a05:6e02:2162:b0:319:ac45:56f4 with SMTP id s2-20020a056e02216200b00319ac4556f4mr27607624ilv.7.1678706413897;
        Mon, 13 Mar 2023 04:20:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678706413; cv=none;
        d=google.com; s=arc-20160816;
        b=hZwWj0oKAOyTGJuf5KRSV8/ByVgpn0VADZYihIhWokzuWmfLc82EPeFSF5WL40Xffm
         NREspVXaJt3har+VGpK0UMWXZnLaprgz9K/cEvZpTXERzmDhnvfvBY3fcm8ARsQY5ErB
         Srv7r4WIM5FD/sngU+v8wSxdExZ6H3Lz/eBw7lPNfg3V3c/p9umzs1GtIjBwkkjbNRs9
         lfdfAo/23yRJYSpjMwBJlomEpzeI42VgMQ3vymj+kwhpJ5uOafxrZ/dxUpk12Zr0TZnC
         GgUm0wC9kzEewK+JvtjTNTV9b3FPJcRCPjLUeMqDKZ2ab9rHTICkIpEtJkBH01wLqNbO
         O/+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=f14X/ekEJo+asb6jqyI54N+VrZQu/Re9k1fW8wvqQYw=;
        b=h2SSYlDld9sQfxXvGnYReXKlPwmvO5SW8aUnBbWEutP1ZFfTKBxsRu8giWB7y3X1rt
         FInwB/QJKImxUDzcH6ScVNJv2kwQ+p+32TLcSdoRhxkvdbPtwGC5qBuwzaVkREbahbui
         Zfeq6//ZN8+AqmeA3POd61PIvJy2d8ABftDoRPKvN7PmJAZcOfd5xj35fSfv++lGkFXp
         ykDO/ZFFbdfCuwtT6/PqEtMHRaIwxgSm5lgBYJDa6C/YVHqmsSJmpVLz2tIzZ7nOx7Cc
         9c3tZLhSQ4rtzNTonj5umy+faaVCZPw2W925pMXKTquSkAGbRlS7mRNX0xl1PQ8n4EKC
         Ikyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dDpkCQjC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2a.google.com (mail-io1-xd2a.google.com. [2607:f8b0:4864:20::d2a])
        by gmr-mx.google.com with ESMTPS id b12-20020a056638150c00b003f6e4b44e5csi898579jat.6.2023.03.13.04.20.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Mar 2023 04:20:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) client-ip=2607:f8b0:4864:20::d2a;
Received: by mail-io1-xd2a.google.com with SMTP id k17so4862392iob.1
        for <kasan-dev@googlegroups.com>; Mon, 13 Mar 2023 04:20:13 -0700 (PDT)
X-Received: by 2002:a02:634e:0:b0:3e5:a7d9:17f0 with SMTP id
 j75-20020a02634e000000b003e5a7d917f0mr15783958jac.4.1678706413368; Mon, 13
 Mar 2023 04:20:13 -0700 (PDT)
MIME-Version: 1.0
References: <bc919c144f8684a7fd9ba70c356ac2a75e775e29.1678491668.git.andreyknvl@google.com>
 <59f433e00f7fa985e8bf9f7caf78574db16b67ab.1678491668.git.andreyknvl@google.com>
In-Reply-To: <59f433e00f7fa985e8bf9f7caf78574db16b67ab.1678491668.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 13 Mar 2023 12:19:30 +0100
Message-ID: <CANpmjNMpjREcMc2iUS2ycUih9SRbP93mUaNPXcDZAd-ZDT2d+g@mail.gmail.com>
Subject: Re: [PATCH 5/5] kasan: suppress recursive reports for HW_TAGS
To: andrey.konovalov@linux.dev
Cc: Catalin Marinas <catalin.marinas@arm.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Will Deacon <will@kernel.org>, 
	linux-arm-kernel@lists.infradead.org, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	Weizhao Ouyang <ouyangweizhao@zeku.com>, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=dDpkCQjC;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2a as
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

On Sat, 11 Mar 2023 at 00:43, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> KASAN suppresses reports for bad accesses done by the KASAN reporting
> code. The reporting code might access poisoned memory for reporting
> purposes.
>
> Software KASAN modes do this by suppressing reports during reporting
> via current->kasan_depth, the same way they suppress reports during
> accesses to poisoned slab metadata.
>
> Hardware Tag-Based KASAN does not use current->kasan_depth, and instead
> resets pointer tags for accesses to poisoned memory done by the reporting
> code.
>
> Despite that, a recursive report can still happen:
>
> 1. On hardware with faulty MTE support. This was observed by Weizhao
>    Ouyang on a faulty hardware that caused memory tags to randomly change
>    from time to time.
>
> 2. Theoretically, due to a previous MTE-undetected memory corruption.
>
> A recursive report can happen via:
>
> 1. Accessing a pointer with a non-reset tag in the reporting code, e.g.
>    slab->slab_cache, which is what Weizhao Ouyang observed.
>
> 2. Theoretically, via external non-annotated routines, e.g. stackdepot.
>
> To resolve this issue, resetting tags for all of the pointers in the
> reporting code and all the used external routines would be impractical.
>
> Instead, disable tag checking done by the CPU for the duration of KASAN
> reporting for Hardware Tag-Based KASAN.
>
> Without this fix, Hardware Tag-Based KASAN reporting code might deadlock.
>
> Fixes: 2e903b914797 ("kasan, arm64: implement HW_TAGS runtime")
> Reported-by: Weizhao Ouyang <ouyangweizhao@zeku.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> ---
>
> Considering that 1. the bug this patch fixes was only observed on faulty
> MTE hardware, and 2. the patch depends on the other patches in this series,
> I don't think it's worth backporting it into stable.
> ---
>  mm/kasan/report.c | 59 ++++++++++++++++++++++++++++++++++++++---------
>  1 file changed, 48 insertions(+), 11 deletions(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 89078f912827..77a88d85c0a7 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -72,10 +72,18 @@ static int __init kasan_set_multi_shot(char *str)
>  __setup("kasan_multi_shot", kasan_set_multi_shot);
>
>  /*
> - * Used to suppress reports within kasan_disable/enable_current() critical
> - * sections, which are used for marking accesses to slab metadata.
> + * This function is used to check whether KASAN reports are suppressed for
> + * software KASAN modes via kasan_disable/enable_current() critical sections.
> + *
> + * This is done to avoid:
> + * 1. False-positive reports when accessing slab metadata,
> + * 2. Deadlocking when poisoned memory is accessed by the reporting code.
> + *
> + * Hardware Tag-Based KASAN instead relies on:
> + * For #1: Resetting tags via kasan_reset_tag().
> + * For #2: Supression of tag checks via CPU, see report_suppress_start/end().

Typo: "Suppression"

>   */
> -static bool report_suppressed(void)
> +static bool report_suppressed_sw(void)
>  {
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>         if (current->kasan_depth)
> @@ -84,6 +92,30 @@ static bool report_suppressed(void)
>         return false;
>  }
>
> +static void report_suppress_start(void)
> +{
> +#ifdef CONFIG_KASAN_HW_TAGS
> +       /*
> +        * Disable migration for the duration of printing a KASAN report, as
> +        * hw_suppress_tag_checks_start() disables checks on the current CPU.
> +        */
> +       migrate_disable();

This still allows this task to be preempted by another task. If the
other task is scheduled in right after hw_suppress_tag_checks_start()
then there won't be any tag checking in that task. If HW-tags KASAN is
used as a mitigation technique, that may unnecessarily weaken KASAN,
because right after report_suppress_start(), it does
spin_lock_irqsave() which disables interrupts (and thereby preemption)
anyway.

Why not just use preempt_disable()?

> +       hw_suppress_tag_checks_start();
> +#else
> +       kasan_disable_current();
> +#endif
> +}
> +
> +static void report_suppress_stop(void)
> +{
> +#ifdef CONFIG_KASAN_HW_TAGS
> +       hw_suppress_tag_checks_stop();
> +       migrate_enable();
> +#else
> +       kasan_enable_current();
> +#endif
> +}
> +
>  /*
>   * Used to avoid reporting more than one KASAN bug unless kasan_multi_shot
>   * is enabled. Note that KASAN tests effectively enable kasan_multi_shot
> @@ -174,7 +206,7 @@ static void start_report(unsigned long *flags, bool sync)
>         /* Do not allow LOCKDEP mangling KASAN reports. */
>         lockdep_off();
>         /* Make sure we don't end up in loop. */
> -       kasan_disable_current();
> +       report_suppress_start();
>         spin_lock_irqsave(&report_lock, *flags);
>         pr_err("==================================================================\n");
>  }
> @@ -192,7 +224,7 @@ static void end_report(unsigned long *flags, void *addr)
>                 panic("kasan.fault=panic set ...\n");
>         add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
>         lockdep_on();
> -       kasan_enable_current();
> +       report_suppress_stop();
>  }
>
>  static void print_error_description(struct kasan_report_info *info)
> @@ -480,9 +512,13 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_ty
>         struct kasan_report_info info;
>
>         /*
> -        * Do not check report_suppressed(), as an invalid-free cannot be
> -        * caused by accessing slab metadata and thus should not be
> -        * suppressed by kasan_disable/enable_current() critical sections.
> +        * Do not check report_suppressed_sw(), as an invalid-free cannot be
> +        * caused by accessing poisoned memory and thus should not be suppressed
> +        * by kasan_disable/enable_current() critical sections.
> +        *
> +        * Note that for Hardware Tag-Based KASAN, kasan_report_invalid_free()
> +        * is triggered by explicit tag checks and not by the ones performed by
> +        * the CPU. Thus, reporting invalid-free is not suppressed as well.
>          */
>         if (unlikely(!report_enabled()))
>                 return;
> @@ -517,7 +553,7 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
>         unsigned long irq_flags;
>         struct kasan_report_info info;
>
> -       if (unlikely(report_suppressed()) || unlikely(!report_enabled())) {
> +       if (unlikely(report_suppressed_sw()) || unlikely(!report_enabled())) {
>                 ret = false;
>                 goto out;
>         }
> @@ -549,8 +585,9 @@ void kasan_report_async(void)
>         unsigned long flags;
>
>         /*
> -        * Do not check report_suppressed(), as kasan_disable/enable_current()
> -        * critical sections do not affect Hardware Tag-Based KASAN.
> +        * Do not check report_suppressed_sw(), as
> +        * kasan_disable/enable_current() critical sections do not affect
> +        * Hardware Tag-Based KASAN.
>          */
>         if (unlikely(!report_enabled()))
>                 return;
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMpjREcMc2iUS2ycUih9SRbP93mUaNPXcDZAd-ZDT2d%2Bg%40mail.gmail.com.
