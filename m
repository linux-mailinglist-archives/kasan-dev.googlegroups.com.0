Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZ6FVOAAMGQEQI77WVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id A5D0130058B
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 15:36:24 +0100 (CET)
Received: by mail-oi1-x238.google.com with SMTP id l1sf2205679oib.10
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 06:36:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611326183; cv=pass;
        d=google.com; s=arc-20160816;
        b=cN8kUX/0kRdAm5jQE6jRiZGByXCCNhWGU2ciT/O69NQoPEhhSb//7Raic3+kh8myqL
         Y/HG7lHo9ZYGzBgU0nGhoPymkglg+ILfC9qkYZze4YMuytpW3P7c9taRKIYhCYkGutUP
         Zuiy7BCqAoGLwXvpCAL0DBXAPWAWZOFVZhZUIuhRrZI72L9pTtyRe2qiFKOI/2MONFT1
         N0XsMdu9iqf2FqxtZA/BW2bw9f/IGeB81iKj8p4I2U8l13Xt17TKB/EmxYkFLMg5twVU
         RvsvM3xdeICtQV/NI0AdnBA0zusSzL8WZijfwl7ft6OuLZ4tbOzEfCjlrLqfVfm4HztT
         kvhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=SaAlrFRIXj3sWQ5kIroUb6UawOLG8pInc4PoTX6yTpk=;
        b=oSqsFWAN2HUaMsLh0NSDDN7dVgigk0BMCma8a81R4hyFlqYMJJjObxnUuf1Q47tfta
         xrq+8JpN8FAaFYvjIEdybM+Kj2nCqSz2mXLMVUaUXxEvAuKiEIAw7y974T56OGROC5hL
         W1Yf+dIy0hefG2ZGLaHrKZq+2AO+fbe7Ccdz8nSQELVGqoJ3DFo5vc/DAjJu5d2vSkjY
         k2lbQlLRH/w+7gJTEq6kdTAWrzVughhDo0uCjGJh4bNJMh8nYjrXPN6X+f1EDsCN4dVO
         YTFGjmKAEfkyfiYkQfFUpghkxW7z5rsK/3/AHzCKUYaU4hFPS+r4WS1CGvk2oPksFDZ3
         Cg5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s1JMK3gv;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SaAlrFRIXj3sWQ5kIroUb6UawOLG8pInc4PoTX6yTpk=;
        b=A8QDUqe9sDq2rR4BGTADbxDV2flHznUyBCIWYkiTwvf2yVPrpkp8lb0lYi2pMV5M/W
         3ARR0M5eVoJOCyOs/L5YBoHnv7HpQt7ZsWpnBnATPMegARNAGNNWFEDvBa1L7UKeDYET
         PjllVdbIUWvGQy7Uf7JbuSzkBKOlWeQnGZZ9xPYQ1A915lRlDGxoBFl77agRNaT+NMRU
         gIYnmV8lkKkTO3YfIFoQrTE1Mb0KdpDxkAE5F/RjFDBR10sTcM/PckhqaPQIPZWn/DGD
         sshUJWLM46DGKHqREn8mMGIkXv11LCLhMLtcqQ55hyGri1sVgNJJ6/tuAcmpc0VAbP/z
         /dtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SaAlrFRIXj3sWQ5kIroUb6UawOLG8pInc4PoTX6yTpk=;
        b=WynrQ1Mkh3BVLYi4WIZBb6O2UGLHt37Phn6BqNh9QsXA1G94dugSYDf+lVoEo1oJAC
         FJRUyYHVzNDAodkgI2/vPLhFVc1CjMkl1wFSmpA0f4mxVd27kKIGXjT93mZPT6EJkIdo
         I3KzrvqUcRnB8V9xLfGSusI6IV2A+yfLZCIaYqiYGtneaNxDFifRFUXVf/DtU3VxdWKG
         5J+x3kQG8aeHmQ7j2KzmtWIDhEPZ4iu5J2oX8OpvGdKWqnpu3T4tqNns8sgPrECRPkg1
         rujEefk1wY5UY8FUS+rQJtsl+mhdYFJ+FQHCYkLYdeXYmUW9CowspqVfVrkV2YCcGUcP
         soVg==
X-Gm-Message-State: AOAM531B6gILktEaH1ccONaPKC6mssykBWofeA5njVh0AzKnU/TQQbgH
	Eqq+SaLUaKPgiuyt/GBZW8U=
X-Google-Smtp-Source: ABdhPJzPntZ7CuQzgOEAQiBCRbC/MpoS+HpEhVjCf7Dxnid1z4JX1oCay5Wh6r49i66CPW7Emcjfrw==
X-Received: by 2002:a9d:4d05:: with SMTP id n5mr3526481otf.99.1611326183672;
        Fri, 22 Jan 2021 06:36:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:3cb:: with SMTP id s11ls32818ooj.5.gmail; Fri, 22
 Jan 2021 06:36:23 -0800 (PST)
X-Received: by 2002:a4a:e718:: with SMTP id y24mr3912510oou.91.1611326183323;
        Fri, 22 Jan 2021 06:36:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611326183; cv=none;
        d=google.com; s=arc-20160816;
        b=cdpJQ/FA56TJ1mQOS9IgDdHnI0KEl36KXp4YBSBg59NO92fkAavHRwxwjNCUFFvamz
         jLb4/SlPV8jMhMOZy3+wiq5z/LR6fSgHyAV2kh2sn3QAKEtbYQUryVasEVXcxnJv6o6e
         CBB4qR8zBGBSwGndAFjovza6x0jqgXnBzLHemjhbtkjsnUhO8WEcorIgjlWYlxelSAJH
         mtBsDf2fHg8+xlmMQj0lFT0YAdg3arHPLe79UbWNix7yMCIh7304AKWZcqyXns81ObyX
         9nC2zDEa7NnL7cY7ca3pUE231OhV+q6E7E0nIptCyjkjseRSBl3UCANQjlOL1ncGqX3Z
         e+iA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=T4ndQifpB6vRYXO2w5aSIQgzTLZUsKUzNWBDOARv8pU=;
        b=zcwiiPGn0b2+1nN8kt5hQB/e9x4W2wAholCBxt2TWpkH8P+slBoMFwOFw2TxYwcxcH
         nZlcApCFhNzCD+l43efBV921FBqgMIL0Z4FfsRbSCAhjgv2dEnbBxj4+tnubF2PMljB3
         IP+CQkC/IlSXZX5H74vxmKRMiHRgNEHJknDSlaPSL0xbPMiOdSctClZQ8PxshNocUwpE
         85vmITVpoJcR4pT1NYSjET6YbZSXdVbuaMssCrRTpvOh0qsDJt33lQxL3OhyWUQythq+
         nT/dO3J/TUUYN650hsqxSwMP4eZNUGrvkmZ1MGE/761yOWWWXMa92+Pvd5jsoNnSTQIs
         jQdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s1JMK3gv;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id l126si549706oih.3.2021.01.22.06.36.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Jan 2021 06:36:23 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id x18so3281144pln.6
        for <kasan-dev@googlegroups.com>; Fri, 22 Jan 2021 06:36:23 -0800 (PST)
X-Received: by 2002:a17:90b:350b:: with SMTP id ls11mr5726685pjb.166.1611326182815;
 Fri, 22 Jan 2021 06:36:22 -0800 (PST)
MIME-Version: 1.0
References: <20210122141125.36166-1-vincenzo.frascino@arm.com> <20210122141125.36166-3-vincenzo.frascino@arm.com>
In-Reply-To: <20210122141125.36166-3-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 22 Jan 2021 15:36:11 +0100
Message-ID: <CAAeHK+zGkkoW=jqxRyntXQ+n9JU-G071Q7s4gFQSaaSV-T8OTQ@mail.gmail.com>
Subject: Re: [PATCH v7 2/4] kasan: Add KASAN mode kernel parameter
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=s1JMK3gv;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62f
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Fri, Jan 22, 2021 at 3:11 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> Architectures supported by KASAN_HW_TAGS can provide a sync or async mode
> of execution. On an MTE enabled arm64 hw for example this can be identified
> with the synchronous or asynchronous tagging mode of execution.
> In synchronous mode, an exception is triggered if a tag check fault occurs.
> In asynchronous mode, if a tag check fault occurs, the TFSR_EL1 register is
> updated asynchronously. The kernel checks the corresponding bits
> periodically.
>
> KASAN requires a specific kernel command line parameter to make use of this
> hw features.
>
> Add KASAN HW execution mode kernel command line parameter.
>
> Note: This patch adds the kasan.mode kernel parameter and the
> sync/async kernel command line options to enable the described features.
>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  Documentation/dev-tools/kasan.rst |  9 +++++++++
>  lib/test_kasan.c                  |  2 +-
>  mm/kasan/hw_tags.c                | 32 ++++++++++++++++++++++++++++++-
>  mm/kasan/kasan.h                  |  6 ++++--
>  4 files changed, 45 insertions(+), 4 deletions(-)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index e022b7506e37..e3dca4d1f2a7 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -161,6 +161,15 @@ particular KASAN features.
>
>  - ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
>
> +- ``kasan.mode=sync`` or ``=async`` controls whether KASAN is configured in
> +  synchronous or asynchronous mode of execution (default: ``sync``).
> +  Synchronous mode: a bad access is detected immediately when a tag
> +  check fault occurs.
> +  Asynchronous mode: a bad access detection is delayed. When a tag check
> +  fault occurs, the information is stored in hardware (in the TFSR_EL1
> +  register for arm64). The kernel periodically checks the hardware and
> +  only reports tag faults during these checks.
> +
>  - ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
>    traces collection (default: ``on`` for ``CONFIG_DEBUG_KERNEL=y``, otherwise
>    ``off``).
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index d16ec9e66806..7285dcf9fcc1 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -97,7 +97,7 @@ static void kasan_test_exit(struct kunit *test)
>                         READ_ONCE(fail_data.report_found));     \
>         if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {                 \
>                 if (READ_ONCE(fail_data.report_found))          \
> -                       hw_enable_tagging();                    \
> +                       hw_enable_tagging_sync();               \
>                 migrate_enable();                               \
>         }                                                       \
>  } while (0)
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index e529428e7a11..308a879a3798 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -25,6 +25,12 @@ enum kasan_arg {
>         KASAN_ARG_ON,
>  };
>
> +enum kasan_arg_mode {
> +       KASAN_ARG_MODE_DEFAULT,
> +       KASAN_ARG_MODE_SYNC,
> +       KASAN_ARG_MODE_ASYNC,
> +};
> +
>  enum kasan_arg_stacktrace {
>         KASAN_ARG_STACKTRACE_DEFAULT,
>         KASAN_ARG_STACKTRACE_OFF,
> @@ -38,6 +44,7 @@ enum kasan_arg_fault {
>  };
>
>  static enum kasan_arg kasan_arg __ro_after_init;
> +static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
>  static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
>  static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
>
> @@ -68,6 +75,21 @@ static int __init early_kasan_flag(char *arg)
>  }
>  early_param("kasan", early_kasan_flag);
>
> +/* kasan.mode=sync/async */
> +static int __init early_kasan_mode(char *arg)
> +{
> +       /* If arg is not set the default mode is sync */
> +       if ((!arg) || !strcmp(arg, "sync"))
> +               kasan_arg_mode = KASAN_ARG_MODE_SYNC;
> +       else if (!strcmp(arg, "async"))
> +               kasan_arg_mode = KASAN_ARG_MODE_ASYNC;
> +       else
> +               return -EINVAL;
> +
> +       return 0;
> +}
> +early_param("kasan.mode", early_kasan_mode);
> +
>  /* kasan.stacktrace=off/on */
>  static int __init early_kasan_flag_stacktrace(char *arg)
>  {
> @@ -115,7 +137,15 @@ void kasan_init_hw_tags_cpu(void)
>                 return;
>
>         hw_init_tags(KASAN_TAG_MAX);
> -       hw_enable_tagging();
> +
> +       /*
> +        * Enable async mode only when explicitly requested through
> +        * the command line.
> +        */
> +       if (kasan_arg_mode == KASAN_ARG_MODE_ASYNC)
> +               hw_enable_tagging_async();
> +       else
> +               hw_enable_tagging_sync();
>  }
>
>  /* kasan_init_hw_tags() is called once on boot CPU. */
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 07ef7fc742ad..3923d9744105 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -294,7 +294,8 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>  #define arch_set_mem_tag_range(addr, size, tag) ((void *)(addr))
>  #endif
>
> -#define hw_enable_tagging()                    arch_enable_tagging()
> +#define hw_enable_tagging_sync()               arch_enable_tagging_sync()
> +#define hw_enable_tagging_async()              arch_enable_tagging_async()
>  #define hw_init_tags(max_tag)                  arch_init_tags(max_tag)
>  #define hw_set_tagging_report_once(state)      arch_set_tagging_report_once(state)
>  #define hw_get_random_tag()                    arch_get_random_tag()
> @@ -303,7 +304,8 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>
>  #else /* CONFIG_KASAN_HW_TAGS */
>
> -#define hw_enable_tagging()
> +#define hw_enable_tagging_sync()
> +#define hw_enable_tagging_async()
>  #define hw_set_tagging_report_once(state)
>
>  #endif /* CONFIG_KASAN_HW_TAGS */
> --
> 2.30.0
>

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzGkkoW%3DjqxRyntXQ%2Bn9JU-G071Q7s4gFQSaaSV-T8OTQ%40mail.gmail.com.
