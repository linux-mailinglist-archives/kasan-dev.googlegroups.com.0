Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAX5WSDQMGQENBUUEKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id C35C03C6B17
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jul 2021 09:19:31 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id k2-20020a5d8b020000b029050b6f9cfe31sf13731657ion.11
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jul 2021 00:19:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626160770; cv=pass;
        d=google.com; s=arc-20160816;
        b=0X45j+2B7j82FlbvL/wRzj/gXjNp2Ya8hjN8OZTPxoP1G7pnCHn7j0UZDx66w/aPFx
         AziWGXdpjhs1WtBlmU7wBeTAJ1BOObKq8d39kQ0t+/fGntdhvTkiGiu0bM/Ndszx2n8I
         R4h5lwCOizuHsejS8v5GOVk5Vlr+e07LLP6ko+zk0c3sNIvOG4eejfANBKJNAZomq+R4
         gc5exOB2oh7jvDJohY85Tu+0mE4g+31BN47eP12abqY3AlXKsObFLSNvcwY0O4XBdiEA
         +H0ts8M37eWsKLGKmPmKLL7kCtJhUaqv4m2bgeJdHgpY6c+XMLC1NF7wVhHCkYGAnFTV
         oTTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YvX3Y6LakxsBLCV+jfvVttzquhEKhsT0UwYdZSsLOf4=;
        b=EpjOPQ7q0dnquy2bwSscbA3c8e+Rt0JBuFS03EMlonQxGLywirihk9GcPm3aeYIWF7
         F3ebq+w7IeA6pjYtmWafH2Ar6WVn2nuyXm5IJLs/BbOKZSFmyFEF3YE4+VkfV6MZuK3w
         ukTUav3FjeNRL1LcFcPF0ayWw/Ob2i+CD0nlzVInDlKQGL7Hn8Uim5oWPiJkBDnTsKLx
         KLczLpgtm4h7hK0JB4SXNSpGML+7IaVHs4urYtNGlGZc4wu1SDp4sQ/J4VnUGuGhSHPe
         NUyi0PJNE14MmCoBWAFjry78fkUNuifr9goUjTvIz6jiQX4wfShf3Oz/n1ccHX0zsFGz
         DrCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nMXBQToF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YvX3Y6LakxsBLCV+jfvVttzquhEKhsT0UwYdZSsLOf4=;
        b=lf7jIbuu7G4tM8RV4Vf+qUiRCp8X4Q22CrMym0sGVTq1wxc2iuv3t8p+fPbBPIGbRm
         Pb7noVynkjaviBr0graVGB1N8V7w48s4hCrZtMsnf95kGEr/+lnLQEcqXCPJ71NzAeEN
         noMr9kV7SCTs15vN1svXqwXZiJUdaMxI0T1/GqPbHpNSia1+MfOL9Jdk2jKPhnJRFKWR
         7zSTUGo+wsFEVVQsh/CJ9/7UNHuaTL7+StcMSmY3NvCoITtT6DZbdLUzwOYRB3LQvW5c
         RqVp3uMjsi+cqeKnXzDV32jb37xJqKIz/U/bE1bf3DcTJXUCUvl/dkUBbEqPmk3OUtzU
         yhLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YvX3Y6LakxsBLCV+jfvVttzquhEKhsT0UwYdZSsLOf4=;
        b=uBUCHEkz74fG5nNLMjf6qBRNl90PfZRBGoQk+PKCN+lmyVqMOFQOiX7EXvSI9AlVdP
         yf3LVdHPlsVKU2mVYKp/0WOGG3IsccDtmewHbgU7yZw7imlg3KtWV/nfiLKNu6qdPQF2
         MRrA0k4YVIPY1a+WeNhR185cpWsHhmS996PnvrrJYfHlUvuNRJyHdqophKCtYrxSTRD1
         ZqjENNGgkjg94AJn+bWTIXCVVgtWzL8jCcvyei6ifSGkCAANXJRt/CV+RqVjE4E3lprY
         5/be6RxtCpWzGv8BxlSPnZsbWv/YbwpetrwPYj7qBYHv2NGPKM6oJu/eQPaYFrtzwwcr
         1gkQ==
X-Gm-Message-State: AOAM530bTYtCbrLX3YTE2xTEncO8rjRouUwQBrG4ZozGP28BHZ0gJCHr
	IAxWdQM7zLZKtoI0b4Y1VeM=
X-Google-Smtp-Source: ABdhPJwcMbL1tWm48ILSX+UTHPDIB62cKGnuh0Ov4glUC+BDrIBm/4eD42DkeTOGFIm1SpsR2w2JLw==
X-Received: by 2002:a05:6638:6a6:: with SMTP id d6mr2699761jad.118.1626160770331;
        Tue, 13 Jul 2021 00:19:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:134c:: with SMTP id u12ls671183jad.8.gmail; Tue, 13
 Jul 2021 00:19:30 -0700 (PDT)
X-Received: by 2002:a02:942e:: with SMTP id a43mr2789508jai.74.1626160770030;
        Tue, 13 Jul 2021 00:19:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626160770; cv=none;
        d=google.com; s=arc-20160816;
        b=fcbvILxm3V+Oer5uu+MIIaYdrp/b40eOQ5Yq9k3hy6gKF3N//Ag47nDIjOY48o1XIJ
         ZO+e5RBPnTopKimO5SYUkND+E6hJHsqvNAoIqqh9ZpwG3gBqjPbVxBSHHNxjQhO45hPz
         SlHiF2r3zsEERJ94M/5EKJ0GONVFi1AGZNzM3Q8dbKEGrf0Fo97afutGnrW3vCikw5Qs
         oBFroVqyGlMVyMXJctFFtuABkgZOQLts2XfbZdfYj6v+dPgxg1dqbxRObHN5B0AULANA
         BiBDs07hhyXvtaSKWRY0Cm0bYKQaDnFe6+w2/4kbAt/N54yVoo/MtS+Yl5W0Brc5HedQ
         HdTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=c1rkHHVlFsycr+ncfeipxll+Ui5VSi+Znz668tHLipE=;
        b=pALGgw3/HihyUfaU4LXmgdB+jsj2MRDbbhmeWXpJEkzClQunhFiZnI4gKAadXxgrt7
         bqC0ZBOvDKENgT7x6Atejk/9KC66B1c6ie/H+nKNA9PDTeo84O4KoZZEIVPcd7ZXyl1T
         c2jNr9kQvsBaHDIyjsFtk2GlI5jjQmhI2MSWQbHULTHL2MTLSuFQHa2AMr6y3yAjYnO4
         Ge/R5xCa3YpcZ2bGSfquZW4bQ5VFl6RL31n5x69W7zKdbZpmPXaxgwLCe3dQsJoVhU9y
         DuLiisI00EuRAPoSIVL1WO+CG44to2j0zFUuWr7AmQpjTx8uwrjpqGYsd95p9830m1g6
         5PMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nMXBQToF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32d.google.com (mail-ot1-x32d.google.com. [2607:f8b0:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id h1si1783362iow.1.2021.07.13.00.19.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Jul 2021 00:19:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) client-ip=2607:f8b0:4864:20::32d;
Received: by mail-ot1-x32d.google.com with SMTP id h24-20020a9d64180000b029036edcf8f9a6so21568661otl.3
        for <kasan-dev@googlegroups.com>; Tue, 13 Jul 2021 00:19:30 -0700 (PDT)
X-Received: by 2002:a05:6830:905:: with SMTP id v5mr2485146ott.17.1626160769409;
 Tue, 13 Jul 2021 00:19:29 -0700 (PDT)
MIME-Version: 1.0
References: <20210713010536.3161822-1-woodylin@google.com>
In-Reply-To: <20210713010536.3161822-1-woodylin@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 13 Jul 2021 09:19:17 +0200
Message-ID: <CANpmjNPH9TcZL9bNdNFqMGQpHMyAQAGWrWvAA6XzuYeO=VocEg@mail.gmail.com>
Subject: Re: [PATCH v2] mm/kasan: move kasan.fault to mm/kasan/report.c
To: Woody Lin <woodylin@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Jonathan Corbet <corbet@lwn.net>, Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nMXBQToF;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as
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

On Tue, 13 Jul 2021 at 03:07, Woody Lin <woodylin@google.com> wrote:
> Move the boot parameter 'kasan.fault' from hw_tags.c to report.c, so it
> can support all KASAN modes - generic, and both tag-based.
>
> Signed-off-by: Woody Lin <woodylin@google.com>

Reviewed-by: Marco Elver <elver@google.com>

Thank you.

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

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPH9TcZL9bNdNFqMGQpHMyAQAGWrWvAA6XzuYeO%3DVocEg%40mail.gmail.com.
