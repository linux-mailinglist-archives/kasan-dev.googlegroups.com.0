Return-Path: <kasan-dev+bncBDW2JDUY5AORBOV4W6DQMGQEGLXD37I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D20F3C7693
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jul 2021 20:40:59 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id q64-20020a2e5c430000b02901864030a0ecsf9506014ljb.2
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jul 2021 11:40:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626201659; cv=pass;
        d=google.com; s=arc-20160816;
        b=PJh4mdJwhVSwsA6XIBADWJ0v2nDU0WdGrErMZfpQK7XlCO35oIlZlXE0nx9z2J8EjD
         e7YLtV4aJfDg4rxBa3kGpesQrn0Crjw7aSkNwvA/Br4WWtOpXOab1QqnooiqEBr4JJUM
         KatC/bv1Cw5zRZmeDw9PVTwPqpCy+NBhGoCMuGkfne95kQqSKXAwMVHawNcVzaV5EJ1D
         zsyJZgSbUgvLKikuyYfhW41sz0xTj2WKwyamRCyXeAfcFyA78Kqyj3YU6nU186xZrztH
         9FoJgcbvMKRH2IT5DnrVBww1/RHznMQc9fLWgTVyfeHGbplMKT91ua4b/X+PruwD7UYd
         L1SA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=YQqom6/sFYuK9ZKvpVi3oSSoqRgPa4TKj63hcMV0L6M=;
        b=ja4WFE44+d98iTcLFtjUAIEG3tRdrRISWJrCmVhex3qZyBl6mUrro+sCGL+IIdyiu+
         j5ztCOX2FC9s3xTc16pJq9/lo+JzPZl9kMIsp5yRpaEEmefAjZ2BQJx2qwhhg2szqKVj
         d/i8fxj9XYhW5DLsjNOM/8m4xpkLz+O0hulway79JaSfHtGuF91F2yE2bgrd2XiqVnmP
         i3JdOymocy2MhiG5e78FatApKBAcaU3ddRt6mswPr8h3r/Cn9IwR12+gWWv/BlrZvs8w
         4uxGK9jbGpTnmJd8ssRDmdU4jIZGOY+EWtriL/MV85tCzXa9ePFseX3wi+FUBHipz9L/
         FTbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="gI7n/qI/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YQqom6/sFYuK9ZKvpVi3oSSoqRgPa4TKj63hcMV0L6M=;
        b=lAvZKHVtw1dgOxgeIcbwTLnwTEAoAJiVtYUH5liCop8dv78WRtkt3+0WfTAzTlUW2y
         L1AT1O9uGsz84Ufc4p+xM8NeTUSYg5/sZ8zBq/qzduchPMJA1tcrGDKbhrt3ju9OOmLo
         zQWMB5DdUNbblnbtVNorFhF2ex7L8EjPBaEHzqr9DhV++6uytrnXMonGE/BXDTny+PSE
         r5qfxd1paPf7giKHKgbdW4F610aZYLPz9XKEPm/KgFZeEAzJcZ4tSv6JJzpVhS7k+rcL
         vnXrBQuOYiIYEM0ZC7q6NapGymCNG3J1qrPL9R7G60A41loGqX0BfFSbkyQoTBhhPO0K
         7zIQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YQqom6/sFYuK9ZKvpVi3oSSoqRgPa4TKj63hcMV0L6M=;
        b=AVExe4+BAlnrPmouQjVm5E2YQo3IXvQnGkGOXCs7HAYgFnrnvkj8n8kk41xsEN33ub
         d16HDlj1orfCcp83xglNFdjByseJweYrip/Z005nKS6N19we7Iqgqc+kjoiNOaKqKkMH
         BaIKdjPAwODdkulkPvYFMV0RDO9wLXY2hh/mbU2Hb8oicqd8JCKVMXybnVMLcrhL6AOL
         QoiCJklZ85qAdAoBo3MgzsyNPBWELBORFOmOm4zBZIgdNx+zEBmaTZymFKMJiooznGxw
         BTMhrnfONeOtmegCD/jR98LH7jpuw+AjyFZ3zkbdjdWiXyf87gBr+sPjZ+fdRpOX6rvL
         THjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YQqom6/sFYuK9ZKvpVi3oSSoqRgPa4TKj63hcMV0L6M=;
        b=mCmwQu91AYLBEOaO3n18tl5rB8vMe1zn79SF6tCRShfWUEtwoWavgaEbjgCSDz8bhe
         /5P3dLyrywNCSt99Vv26lwJpdB56O+2o7efzgg+ZEmw2ZhzMN+XGX9KdAQxwrkcvSl2z
         fEwyB2LxF8WWvdTn+MkdkmS+g0kURzLn09Xb8KAWKQLuuZHEDczzPDC/Xe/r/dOjKvhc
         fcAXTg+Iqh6Vf/SAts2boadgjRZ63trlrVI8TFA0UA2TxxopJKPzVhuEsiun4EsUtuct
         aaXc1lmd4zuUwSCktDMq3BxAEW6B8eVCQGbxLAnaJyuOtYlTa/9jZslOPQDbZxfWIIuo
         +jpw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530mRN/ME/C1X9p01RDfG5AODAhDwVxCpK7rqnvdZF2YlRo7hFGn
	FLfcZJknWYzORnir1UpYvGA=
X-Google-Smtp-Source: ABdhPJxb9qRP9QMy0K5spiL2lUT+v63bNzt64akqivSrezYv+dka7KnKe2Uz4GlzRRz1h4CB6wU/WA==
X-Received: by 2002:a2e:a495:: with SMTP id h21mr5625721lji.60.1626201658871;
        Tue, 13 Jul 2021 11:40:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b88e:: with SMTP id r14ls4288916ljp.7.gmail; Tue, 13 Jul
 2021 11:40:57 -0700 (PDT)
X-Received: by 2002:a2e:9c19:: with SMTP id s25mr5554868lji.478.1626201657731;
        Tue, 13 Jul 2021 11:40:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626201657; cv=none;
        d=google.com; s=arc-20160816;
        b=J8JnbzrbXMvhqW+QxD/NPNyBEVAKqrNIlaUTcK+i0s4m1XcDm7oKWu4j4fFphO1r6A
         ulONbm+OvLYW8JnPLbYfMGZEm5fl8NjEGKnEV0AdND7Mbl74iQB4O2Rm5dCE811gxj66
         fGZqDLeC+J52ZsyKtv6qmXnRxZgKQXtRFtqdQHIl8K+ZzxcJgE5XeD1pUsr2p5l0LMA7
         +5SmngWbsT+iauWQtJDsBFKgnbm9TPJfYfE5g5fLbRXx3xIx42R93Xx90rVW7NZz7zfk
         XyhXxvk8nhZwiy9kY2uJa0ZUSm3aKsW/EUVe+nkZiTpPRCeuyI5hsLDSt/UytwEoVORv
         EHRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QQpf5xOaOqo0s/plb1U3NgMNZX1Ph8Dt44evAisR+l0=;
        b=rA8BOQSAzCSqOrlF3QrVn0c6gjRsizgBhVWHK7qxEQ0/W23rR8XUi1vVy4FATgVpxP
         g7rbqnPsy0kvyXOs+7J/YUsbooc9akjtKe/mtkU/YJaCsPZfAHvIy5/DlXQLp9ngnXn0
         GvzZX9V1Cjwxu+lkOcJp+zTieusf1Ow8bA4jFDpaF5glrc9OuIQqAUr3dUzyXhmyVOAg
         fDaZgV9+bmCUTjGli4RFMbrY1SZwm6UbnP/ds29eg2wsw3tXUcrjhbTc4Cm9vOeLfDYi
         XQw8NNQ25zrnw64W0cxq+UK4WE9O/VX9lChgCauLfiCHe1RkzezipyiyWol977Ck6CXK
         slaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="gI7n/qI/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x62c.google.com (mail-ej1-x62c.google.com. [2a00:1450:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id d9si546930lji.3.2021.07.13.11.40.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Jul 2021 11:40:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62c as permitted sender) client-ip=2a00:1450:4864:20::62c;
Received: by mail-ej1-x62c.google.com with SMTP id o5so43315355ejy.7
        for <kasan-dev@googlegroups.com>; Tue, 13 Jul 2021 11:40:57 -0700 (PDT)
X-Received: by 2002:a17:907:7d94:: with SMTP id oz20mr7376635ejc.333.1626201657390;
 Tue, 13 Jul 2021 11:40:57 -0700 (PDT)
MIME-Version: 1.0
References: <20210713010536.3161822-1-woodylin@google.com>
In-Reply-To: <20210713010536.3161822-1-woodylin@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 13 Jul 2021 20:40:46 +0200
Message-ID: <CA+fCnZdycHhs1fQyn1uZKhPv8T3EhE_ckQ7tVbELyMSEJGJE7Q@mail.gmail.com>
Subject: Re: [PATCH v2] mm/kasan: move kasan.fault to mm/kasan/report.c
To: Woody Lin <woodylin@google.com>
Cc: Marco Elver <elver@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Jonathan Corbet <corbet@lwn.net>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="gI7n/qI/";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62c
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Jul 13, 2021 at 3:07 AM Woody Lin <woodylin@google.com> wrote:
>
> Move the boot parameter 'kasan.fault' from hw_tags.c to report.c, so it
> can support all KASAN modes - generic, and both tag-based.
>
> Signed-off-by: Woody Lin <woodylin@google.com>
> ---
>  Documentation/dev-tools/kasan.rst | 13 ++++++----
>  mm/kasan/hw_tags.c                | 43 -------------------------------
>  mm/kasan/kasan.h                  |  1 -
>  mm/kasan/report.c                 | 29 ++++++++++++++++++---
>  4 files changed, 34 insertions(+), 52 deletions(-)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index 83ec4a556c19..21dc03bc10a4 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -181,9 +181,16 @@ By default, KASAN prints a bug report only for the first invalid memory access.
>  With ``kasan_multi_shot``, KASAN prints a report on every invalid access. This
>  effectively disables ``panic_on_warn`` for KASAN reports.
>
> +Alternatively, independent of ``panic_on_warn`` the ``kasan.fault=`` boot
> +parameter can be used to control panic and reporting behaviour:
> +
> +- ``kasan.fault=report`` or ``=panic`` controls whether to only print a KASAN
> +  report or also panic the kernel (default: ``report``). The panic happens even
> +  if ``kasan_multi_shot`` is enabled.
> +
>  Hardware tag-based KASAN mode (see the section about various modes below) is
>  intended for use in production as a security mitigation. Therefore, it supports
> -boot parameters that allow disabling KASAN or controlling its features.
> +additional boot parameters that allow disabling KASAN or controlling features:
>
>  - ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
>
> @@ -199,10 +206,6 @@ boot parameters that allow disabling KASAN or controlling its features.
>  - ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
>    traces collection (default: ``on``).
>
> -- ``kasan.fault=report`` or ``=panic`` controls whether to only print a KASAN
> -  report or also panic the kernel (default: ``report``). The panic happens even
> -  if ``kasan_multi_shot`` is enabled.
> -
>  Implementation details
>  ----------------------
>
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 4ea8c368b5b8..51903639e55f 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -37,16 +37,9 @@ enum kasan_arg_stacktrace {
>         KASAN_ARG_STACKTRACE_ON,
>  };
>
> -enum kasan_arg_fault {
> -       KASAN_ARG_FAULT_DEFAULT,
> -       KASAN_ARG_FAULT_REPORT,
> -       KASAN_ARG_FAULT_PANIC,
> -};
> -
>  static enum kasan_arg kasan_arg __ro_after_init;
>  static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
>  static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
> -static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
>
>  /* Whether KASAN is enabled at all. */
>  DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
> @@ -59,9 +52,6 @@ EXPORT_SYMBOL_GPL(kasan_flag_async);
>  /* Whether to collect alloc/free stack traces. */
>  DEFINE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
>
> -/* Whether to panic or print a report and disable tag checking on fault. */
> -bool kasan_flag_panic __ro_after_init;
> -
>  /* kasan=off/on */
>  static int __init early_kasan_flag(char *arg)
>  {
> @@ -113,23 +103,6 @@ static int __init early_kasan_flag_stacktrace(char *arg)
>  }
>  early_param("kasan.stacktrace", early_kasan_flag_stacktrace);
>
> -/* kasan.fault=report/panic */
> -static int __init early_kasan_fault(char *arg)
> -{
> -       if (!arg)
> -               return -EINVAL;
> -
> -       if (!strcmp(arg, "report"))
> -               kasan_arg_fault = KASAN_ARG_FAULT_REPORT;
> -       else if (!strcmp(arg, "panic"))
> -               kasan_arg_fault = KASAN_ARG_FAULT_PANIC;
> -       else
> -               return -EINVAL;
> -
> -       return 0;
> -}
> -early_param("kasan.fault", early_kasan_fault);
> -
>  /* kasan_init_hw_tags_cpu() is called for each CPU. */
>  void kasan_init_hw_tags_cpu(void)
>  {
> @@ -197,22 +170,6 @@ void __init kasan_init_hw_tags(void)
>                 break;
>         }
>
> -       switch (kasan_arg_fault) {
> -       case KASAN_ARG_FAULT_DEFAULT:
> -               /*
> -                * Default to no panic on report.
> -                * Do nothing, kasan_flag_panic keeps its default value.
> -                */
> -               break;
> -       case KASAN_ARG_FAULT_REPORT:
> -               /* Do nothing, kasan_flag_panic keeps its default value. */
> -               break;
> -       case KASAN_ARG_FAULT_PANIC:
> -               /* Enable panic on report. */
> -               kasan_flag_panic = true;
> -               break;
> -       }
> -
>         pr_info("KernelAddressSanitizer initialized\n");
>  }
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 98e3059bfea4..9d57383ce1fa 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -36,7 +36,6 @@ static inline bool kasan_async_mode_enabled(void)
>
>  #endif
>
> -extern bool kasan_flag_panic __ro_after_init;
>  extern bool kasan_flag_async __ro_after_init;
>
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 8fff1825b22c..884a950c7026 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -39,6 +39,31 @@ static unsigned long kasan_flags;
>  #define KASAN_BIT_REPORTED     0
>  #define KASAN_BIT_MULTI_SHOT   1
>
> +enum kasan_arg_fault {
> +       KASAN_ARG_FAULT_DEFAULT,
> +       KASAN_ARG_FAULT_REPORT,
> +       KASAN_ARG_FAULT_PANIC,
> +};
> +
> +static enum kasan_arg_fault kasan_arg_fault __ro_after_init = KASAN_ARG_FAULT_DEFAULT;
> +
> +/* kasan.fault=report/panic */
> +static int __init early_kasan_fault(char *arg)
> +{
> +       if (!arg)
> +               return -EINVAL;
> +
> +       if (!strcmp(arg, "report"))
> +               kasan_arg_fault = KASAN_ARG_FAULT_REPORT;
> +       else if (!strcmp(arg, "panic"))
> +               kasan_arg_fault = KASAN_ARG_FAULT_PANIC;
> +       else
> +               return -EINVAL;
> +
> +       return 0;
> +}
> +early_param("kasan.fault", early_kasan_fault);
> +
>  bool kasan_save_enable_multi_shot(void)
>  {
>         return test_and_set_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags);
> @@ -102,10 +127,8 @@ static void end_report(unsigned long *flags, unsigned long addr)
>                 panic_on_warn = 0;
>                 panic("panic_on_warn set ...\n");
>         }
> -#ifdef CONFIG_KASAN_HW_TAGS
> -       if (kasan_flag_panic)
> +       if (kasan_arg_fault == KASAN_ARG_FAULT_PANIC)
>                 panic("kasan.fault=panic set ...\n");
> -#endif
>         kasan_enable_current();
>  }
>
> --
> 2.32.0.93.g670b81a890-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdycHhs1fQyn1uZKhPv8T3EhE_ckQ7tVbELyMSEJGJE7Q%40mail.gmail.com.
