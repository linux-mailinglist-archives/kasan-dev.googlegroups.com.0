Return-Path: <kasan-dev+bncBDX4HWEMTEBRBEG5SWAQMGQEZRU3W6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id EE0A0319185
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 18:51:13 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id b20sf4545157pjh.8
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 09:51:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613065872; cv=pass;
        d=google.com; s=arc-20160816;
        b=BI3heY/pM5yOSisjIm6oyS5CJnFqdnrvBx84JrMqbHbp6vi0IHlm8bPfBZ0wBVfXsQ
         PfRraFzgSfN6JG21AE58EOBKnJb43/yi+K+PT9H8MwiZi3IzaMJ9y1hrbVnETWjBkTmH
         re1/VwPLkUZzjKpxTDmPrHeYCzrzf1U8r78c9aIJuJX2uQbf/1XNd1JTEfi6GLa/uqHT
         e8mJRd+/nI8nMuyzppmR42tk01kWRqZs9lopglPyqXV1FTrKyDPKvjXEiGdVYkzWlJdS
         mxcdZeIk3voIumwCrLw3L7OgspL74WVZJqJbz7YaMtOGJuoS+ErVO+RsCVfe1wbaB3bW
         dL2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2gKgpo3MpPkK09jcUq/rL4Vn9RQRGLGAyD48ldTPvns=;
        b=VOLIVgIXzPLFWbTxTXiKfdCSkb8p089ZXJLZ8N2Tbdawv4l5ReVHgHGU7yO9TUmlxh
         Tr2C1jwey1kkQgJ/enoTkxYhZc2QBpatmCE62eL3TJqnyYrl8TiwZHndsHuaxOrETxtb
         ruTUn3OGivM0x5OUj9K95ClpvQ+x0WvkO9qZ3x8HnS3TgJXVhbHUvxvc0MIX4PGXWiJr
         iS3qywlUqzYZmk1e+hSOg0nBcQ7iVWIxwKcmEhfMAoLIQq2HqFn/fHdfz3zE+eQs1NBP
         ilHNrLg2nZAXkXkK4Un7E/OxppCqHbbfpZVUnfyic94jLdgKc48v/4pmdwuImDsEIN1s
         TV1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DIVMD1rw;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2gKgpo3MpPkK09jcUq/rL4Vn9RQRGLGAyD48ldTPvns=;
        b=k1s8ZpZUJjgMyDQykNsglQ561sjZxk3c5PHBbIDyBRnEA/JwXTJh8o17eipoCmI7n3
         nMS6NMcV9/eLh4tlw9IDkwauLbj7brxIUDh6zGXcKWI/LQ/2vxnPhGFVQUOoGNRjIx1F
         lgdIRzyIjUku9aMnbBwLph4e2UEdsIx1ieWeJNhs4rDNwTUosFPutJRnqC7oMxp3SLxg
         Y81J1tM5Uo/aEPYmNkoW6nknnaEOCQwQMXTMnljk4Nr/NsBWzSl8tTQr5QezmegG38SS
         x+459uJMwYK01ZIn4f+GqvjZdCx6R7X6JppJeSrzZThAe6N6SxaVEXyIklvrsiRI+uiz
         yGjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2gKgpo3MpPkK09jcUq/rL4Vn9RQRGLGAyD48ldTPvns=;
        b=AmzSRj/fEsEA7TZD+sypVW+hFZPTXdlaP9EH3uzhbnxa/1XMP8BMykp/meTIe1eo3U
         lKGt55jUf/u7dHdgcaf2R723dM8d+uhlVLkiB9GcwBsfwOct20GlrcLa1PDqjRwXRn/X
         u9iKnTohvLzUGH8vDjeezaxhbzgnnhfy6PBzWtoeXFn5cLWresbyEzmb9l1SKi2SW8f/
         UittBMbCVZ6uNz7OVXy4aNcKpIQOfp43bHi/MDuacL0dalL8Fub/5oiDgi7mU4uyC9fu
         1PTegmt2OVoopGHiWgmPoqlLjIajFRiJPR5VxtLb7OKpVg5SRwnxfrUSY3/oDbCdGiLp
         4e/w==
X-Gm-Message-State: AOAM530AQAINtA207khyjlm83xuvMzWQ3bKgEBoe//Xw+XZe9hCAMl/q
	dM7GcsSbsch3o97eK8zxptI=
X-Google-Smtp-Source: ABdhPJwjOFnwYhq37nhsNvRSb+aWIvrzstbyZTQ5sVgdabKHWyRsueDnCa2DwFMMgQOG0ZGXDwdU0A==
X-Received: by 2002:a17:902:e541:b029:df:df4f:2921 with SMTP id n1-20020a170902e541b02900dfdf4f2921mr8943179plf.52.1613065872668;
        Thu, 11 Feb 2021 09:51:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ba17:: with SMTP id s23ls3007593pjr.3.canary-gmail;
 Thu, 11 Feb 2021 09:51:12 -0800 (PST)
X-Received: by 2002:a17:90b:4c8c:: with SMTP id my12mr4827269pjb.29.1613065872079;
        Thu, 11 Feb 2021 09:51:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613065872; cv=none;
        d=google.com; s=arc-20160816;
        b=iL7z74Uo5/25wncntM5pK91a0qxSb0KjQLHzb8JXYZz3IR5bpIWaswIfPBsC2BZI8C
         BHR8WJvqWS5m+fKjGby47tUGITj5RTgSepvvQvueLJdyaVS8Ha4NRJzLofGazF/HCyuL
         ojlpLgB/V0wBTX0QarDCso3rlB9im80xnT1Io5fjlBY3W/WZlxHOppv+BOmygNLJQu29
         /UZwSyndLnghcdvJECu0mtI9kmqiDOUIVJ8FdBU2d03kuguFB5UcEMVnogkbY2YzBflk
         lOO/PQeKEh/yHTnhrUAduKNPD/wH6edeLbbcNXM6X8PKWflj2QtXFTN8A1ys+nAyTTFA
         zOCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Vt7Fl48/IoYwLXAX21jt2ptSlKZXuflqfasvRCaCF+Y=;
        b=Va7ersti1zKkaHrepG5YSHjnLbhTpbY48iNWSLVyNK2HTfJA/+H1OQnsKagUF3kph2
         R/Qk8i2U7y62IzRkTcJR8cdTHQMKr625+jOsyRgIzoj/q/Mczs9j4RPYNE665LtSvYdT
         EAq8HyN55jGT7MXa2v3aB3YevgdJieP33rXtSjY/y1+ZK1fWLuEHhvY7M5isaVwJ6+U7
         VjimM7eipQ0uJ6nWwW1F9C7SkL32/caC6NnpNBPVarXMpRR8tHGXrPpKfMf0InXjRVbT
         qfEhHlqBkeqSCi0WUQMwWEEWAAod2H0GqX+x6uWi4bXmggdiipsASE4oz1rjLc4yrXKp
         PDfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DIVMD1rw;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x52a.google.com (mail-pg1-x52a.google.com. [2607:f8b0:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id i23si302620pjl.3.2021.02.11.09.51.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Feb 2021 09:51:12 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52a as permitted sender) client-ip=2607:f8b0:4864:20::52a;
Received: by mail-pg1-x52a.google.com with SMTP id t11so4410897pgu.8
        for <kasan-dev@googlegroups.com>; Thu, 11 Feb 2021 09:51:12 -0800 (PST)
X-Received: by 2002:a63:416:: with SMTP id 22mr9063460pge.286.1613065871687;
 Thu, 11 Feb 2021 09:51:11 -0800 (PST)
MIME-Version: 1.0
References: <20210211153353.29094-1-vincenzo.frascino@arm.com> <20210211153353.29094-3-vincenzo.frascino@arm.com>
In-Reply-To: <20210211153353.29094-3-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Feb 2021 18:50:59 +0100
Message-ID: <CAAeHK+zefPsq6pzO-bTz-xOXQrNkwuCS8i9L7EXLxH=SkKAgJw@mail.gmail.com>
Subject: Re: [PATCH v13 2/7] kasan: Add KASAN mode kernel parameter
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DIVMD1rw;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52a
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

On Thu, Feb 11, 2021 at 4:34 PM Vincenzo Frascino
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
> Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> [ Add a new var instead of exposing kasan_arg_mode to be consistent with
>   flags for other command line arguments. ]
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  Documentation/dev-tools/kasan.rst |  9 ++++++
>  lib/test_kasan.c                  |  2 +-
>  mm/kasan/hw_tags.c                | 52 ++++++++++++++++++++++++++++++-
>  mm/kasan/kasan.h                  |  7 +++--
>  4 files changed, 66 insertions(+), 4 deletions(-)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index ddf4239a5890..6f6ab3ed7b79 100644
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
>    traces collection (default: ``on``).
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 1328c468fdb5..f8c72d3aed64 100644
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
> index 1dfe4f62a89e..bd249d1f6cdc 100644
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
> @@ -45,6 +52,10 @@ static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
>  DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
>  EXPORT_SYMBOL(kasan_flag_enabled);
>
> +/* Whether the asynchronous mode is enabled. */
> +bool kasan_flag_async __ro_after_init;
> +EXPORT_SYMBOL_GPL(kasan_flag_async);
> +
>  /* Whether to collect alloc/free stack traces. */
>  DEFINE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
>
> @@ -68,6 +79,21 @@ static int __init early_kasan_flag(char *arg)
>  }
>  early_param("kasan", early_kasan_flag);
>
> +/* kasan.mode=sync/async */
> +static int __init early_kasan_mode(char *arg)
> +{
> +       /* If arg is not set the default mode is sync */
> +       if ((!arg) || !strcmp(arg, "sync"))

Let's default to KASAN_ARG_MODE_DEFAULT like for other args:

if (!arg)
  return -EINVAL;

kasan_init_hw_tags_cpu()/kasan_init_hw_tags() already handle
KASAN_ARG_MODE_DEFAULT properly.

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
> @@ -115,7 +141,15 @@ void kasan_init_hw_tags_cpu(void)
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
> @@ -132,6 +166,22 @@ void __init kasan_init_hw_tags(void)
>         /* Enable KASAN. */
>         static_branch_enable(&kasan_flag_enabled);
>
> +       switch (kasan_arg_mode) {
> +       case KASAN_ARG_MODE_DEFAULT:
> +               /*
> +                * Default to sync mode.
> +                * Do nothing, kasan_flag_async keeps its default value.
> +                */
> +               break;
> +       case KASAN_ARG_MODE_SYNC:
> +               /* Do nothing, kasan_flag_async keeps its default value. */
> +               break;
> +       case KASAN_ARG_MODE_ASYNC:
> +               /* Async mode enabled. */
> +               kasan_flag_async = true;
> +               break;
> +       }
> +
>         switch (kasan_arg_stacktrace) {
>         case KASAN_ARG_STACKTRACE_DEFAULT:
>                 /* Default to enabling stack trace collection. */
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index cc787ba47e1b..98f70ffc9e1c 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -21,6 +21,7 @@ static inline bool kasan_stack_collection_enabled(void)
>  #endif
>
>  extern bool kasan_flag_panic __ro_after_init;
> +extern bool kasan_flag_async __ro_after_init;
>
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>  #define KASAN_GRANULE_SIZE     (1UL << KASAN_SHADOW_SCALE_SHIFT)
> @@ -294,7 +295,8 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>  #define arch_set_mem_tag_range(addr, size, tag) ((void *)(addr))
>  #endif
>
> -#define hw_enable_tagging()                    arch_enable_tagging()
> +#define hw_enable_tagging_sync()               arch_enable_tagging_sync()
> +#define hw_enable_tagging_async()              arch_enable_tagging_async()
>  #define hw_init_tags(max_tag)                  arch_init_tags(max_tag)
>  #define hw_set_tagging_report_once(state)      arch_set_tagging_report_once(state)
>  #define hw_get_random_tag()                    arch_get_random_tag()
> @@ -303,7 +305,8 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
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

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzefPsq6pzO-bTz-xOXQrNkwuCS8i9L7EXLxH%3DSkKAgJw%40mail.gmail.com.
