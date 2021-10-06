Return-Path: <kasan-dev+bncBDW2JDUY5AORBW5I62FAMGQEW267DHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 41199423D9A
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 14:19:41 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id v10-20020a17090ac90a00b0019fc1829462sf2476486pjt.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 05:19:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633522779; cv=pass;
        d=google.com; s=arc-20160816;
        b=WVDGaP/jZpnf6vhK9fmET7MGkApCRcdAOQ2LnSb/A0TpT/SbK1aD7cRXe+DvIV59VW
         SJm+JIo+hkzcMwYdbaxT0rgt1Nn0b8CoSyQ6toJgsyNwRdz7rxIhdnhj+u2tpmKLa60T
         D4OEJ+0Zjg/E37q27Eo9pcsU2GCVKdan0aX/WZ7auMML0mQ/FEJp1rwkJYVorJ3wTNre
         QIfrzrtgvHSdDDfuDMoRcRAR3pgs/CqmedNTgs8mh1Y4tAJHrnEO8gphoTS/BnsOydM5
         B6nDxb8hfERqP2TPJYTm44wx8JktS6pzsNEfp9/OnzF1sTfjraq3MeNaHvpZkaDXXcFJ
         gonQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=asMJmL9S1LPgY7jDn5oQkApEvq2TSiU0Y6kXS9/ycUM=;
        b=VZntZRwYYY4BN4nlv+cWpwsvc58DY5u7NyoH6N+xIkXvUbuMMP6Qi/t8P3Y2QfhppE
         gtHI0nzHziglC/jfDml+XMdvOuCldokv5fwzDS610otALcyWyfg+nrWPzpjw2M2Mb/jX
         FTrXWwOzQy42ibC9JTzGzLjoe1yz4G8z8j9UL/0a4O6j5LbUPA+yPAghdly2R1rDsEz3
         1+Spjn+Vj7GIk1TIqZm90Vpu1Xum+ZNVfb8qmafl1/Atp5cBzuH05c/EXF3BzmpE0+Z+
         jurOtBDGh7e1ZsSjshFsRsEB5mKGpDJ6eNbRA2lOnb2MkX6F7skmZ514kCTi3SmScwkr
         WSeQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=hqCNaDzb;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=asMJmL9S1LPgY7jDn5oQkApEvq2TSiU0Y6kXS9/ycUM=;
        b=I/+7yhjsbTRpZB+mquR511BKuGQVYx2QiHQK+WkwSTTfZ/a0hIN67Pkp1LQcjryJdY
         cKMWFja7TQXPfuUow1rJATuDq+LaqI/hvwMsWWe1klCpbEmvIeSOBOUWO11qTMLYkDaN
         nJQHlhSYbvlVdYM+ywizyHTjQL77cVclY5KqiCyViYk91InOjTPDdASboA6pmnUqQ62g
         6sKJ+g8W0JgjcasRRTdALlH/bxDhChXVx8NduzhYM2n+ZxsmNxwqGyvYn/KJQgt/fvQf
         nS6VpO7OjW1D4+XgbbQARUuQtM03gJ/+5J4Xh/6CFvv2PukNOzUKaJBwZDUluSBDg6oo
         Epxw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=asMJmL9S1LPgY7jDn5oQkApEvq2TSiU0Y6kXS9/ycUM=;
        b=qKlfvAD/whH9qYAVUZ5hHGhZbXwp18dPfFLj+/e/nUmEeKdrcZF16fT3Bh9b6D/Fko
         LLdg/eNR+t4PMxmsVS7OIwYHP+nIf/3iAa6NQMoxIsixtzXdssnMM9ch/BjHHgPODpCZ
         rOWlEKxOKks1aVq7Tr1gXJTla4rW5T+Nj2q6Ej7+iadw5+Su/OWJqpxNIy+7ziiJVQ3p
         WLnLyQ53WXGjXuPWTjQcnl+r342bvhFNTurLZqLelOZ/pFsC9pMOJIBLxXE4v9062fFr
         hUuuOZ+bceydyZJaS7Jn5GOFNVC7DfcIQfVNNJgjsyOrlNpyJC1r8YTHhIXrxlfGjJhJ
         JaNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=asMJmL9S1LPgY7jDn5oQkApEvq2TSiU0Y6kXS9/ycUM=;
        b=7/oIJiyvFkpeu8KoEPUayqrynHo/K/GuKwBRyikuXKE/gD/S1LeLYHYAV0xBdn9BKo
         NGTii6GjmQLKV09UQVB13NQT7VdC4aJ9/HNhj/K1vyog8y2evfwrmVc8XyEnv5gtX+NF
         P0hAC3zIVTBQdAm6cORgPiAWqWPoVedUO3bSFkWKL23YX4XBHryC1nypV05akXGjW/dt
         oOh2+BtRCSZrEPNIvpIOS1XrN1rUOc4UfRnoFnBMy5RBpde5oAkXXr0K3OyNwb3E4ugf
         NSTvFQv5AkYLBxN+P6XpO4Vx+W2lfgWhTVNuviLGCRVZH5ingHv8ixyw6ylgMZke4vPO
         OC/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ESdEJNMLHY4k7rHb2bjQvJ8sWEkk6Ln7BNmxXv+4mmVBXQ5Qt
	d7c/BcmO5Dsh3NLiS5w0lA4=
X-Google-Smtp-Source: ABdhPJw5v9fpwJfXTAHhtroLjMPKPJgl086tivG/3tnC7bmakUsZX5slFI/zPQOXmwOlwT8XNS+8RA==
X-Received: by 2002:a17:90b:fd2:: with SMTP id gd18mr10662288pjb.219.1633522779775;
        Wed, 06 Oct 2021 05:19:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ba97:: with SMTP id k23ls13690350pls.10.gmail; Wed,
 06 Oct 2021 05:19:39 -0700 (PDT)
X-Received: by 2002:a17:90b:3144:: with SMTP id ip4mr9783766pjb.23.1633522779198;
        Wed, 06 Oct 2021 05:19:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633522779; cv=none;
        d=google.com; s=arc-20160816;
        b=e55uiCf2YkP/v9aLlQuWaJOaO+CA4tCEgVzAm70Qb8leiutl3dQbB7sW+BmPN0jdsZ
         NEN91n6U1twaUWTJ/gkur9KuHZqtuT0BUF20ssLEgGMvpVXEV9Ds8GPac1Mw6ttCf58u
         dbzfie7G7xk5Ep+eSoEj8cPesmH0Dv1CzVnWqhrl3Gp1dI3oCcG9sOP8c9pgFzaobPmJ
         T7asKxHtsWqXu3cRNSV6iKW1YlVaDCVdEo9ECM2Yv3vn18QM0J0jlh1K7eFFUdlc8Ay8
         FZh1MPNY7T6R76kmKEbrE8QfxF+Xbh2rOkqV/HzW4eppRxxaNCrNqc88nOSWba4I/dYk
         uAfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EPyyphJxeyPemnnSLcLAKB5S740xdXOZ+FC+Ivvdl7M=;
        b=oYX7UTMRQ4oHBsRNFve2CbnJFnU9zXv4co12RnT52OdpFNVJ6ZSEPT4E3zA9daDPBG
         qegQUHK1IneHLQvele1Gv2Ss4jxf91puAYeejhLZhdHU4GFvuYyH5ENqZhlly9Sgr8nF
         N0T2B5oZ4eYil2pqnqSrSxgcSFB/2g97z/b5KAcFB6JHC/qFUMydRoitMLJeKKAyg5Q5
         TtH0ZihogHbtVPsheMFX/AECDSRw3HjnJhq8OByQp4KBXFuV49efiAUpH8ijxgwRC7Wd
         MhBDD4UsjEnV7FR90YG7E5zxc5yjYQVZXz3xy3MwrMOaRu2mrUNsy25kutjLrs0+XV4l
         QNjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=hqCNaDzb;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12c.google.com (mail-il1-x12c.google.com. [2607:f8b0:4864:20::12c])
        by gmr-mx.google.com with ESMTPS id o2si521886pjj.1.2021.10.06.05.19.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Oct 2021 05:19:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12c as permitted sender) client-ip=2607:f8b0:4864:20::12c;
Received: by mail-il1-x12c.google.com with SMTP id t11so2607545ilf.11
        for <kasan-dev@googlegroups.com>; Wed, 06 Oct 2021 05:19:39 -0700 (PDT)
X-Received: by 2002:a05:6e02:1d1e:: with SMTP id i30mr7393102ila.248.1633522778960;
 Wed, 06 Oct 2021 05:19:38 -0700 (PDT)
MIME-Version: 1.0
References: <20211004202253.27857-1-vincenzo.frascino@arm.com> <20211004202253.27857-6-vincenzo.frascino@arm.com>
In-Reply-To: <20211004202253.27857-6-vincenzo.frascino@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 6 Oct 2021 14:19:28 +0200
Message-ID: <CA+fCnZfuu3MLgeSJONqKaXMzkBsGxTQYjTtF0_=fMf4dGGQZCw@mail.gmail.com>
Subject: Re: [PATCH v2 5/5] kasan: Extend KASAN mode kernel parameter
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=hqCNaDzb;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12c
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

On Mon, Oct 4, 2021 at 10:23 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> Architectures supported by KASAN_HW_TAGS can provide an asymmetric mode
> of execution. On an MTE enabled arm64 hw for example this can be
> identified with the asymmetric tagging mode of execution. In particular,
> when such a mode is present, the CPU triggers a fault on a tag mismatch
> during a load operation and asynchronously updates a register when a tag
> mismatch is detected during a store operation.
>
> Extend the KASAN HW execution mode kernel command line parameter to
> support asymmetric mode.
>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
> ---
>  Documentation/dev-tools/kasan.rst |  7 +++++--
>  lib/test_kasan.c                  |  2 +-
>  mm/kasan/hw_tags.c                | 27 ++++++++++++++++++++++-----
>  mm/kasan/kasan.h                  | 22 +++++++++++++++++++---
>  mm/kasan/report.c                 |  2 +-
>  5 files changed, 48 insertions(+), 12 deletions(-)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index 21dc03bc10a4..8089c559d339 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -194,14 +194,17 @@ additional boot parameters that allow disabling KASAN or controlling features:
>
>  - ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
>
> -- ``kasan.mode=sync`` or ``=async`` controls whether KASAN is configured in
> -  synchronous or asynchronous mode of execution (default: ``sync``).
> +- ``kasan.mode=sync``, ``=async`` or ``=asymm`` controls whether KASAN
> +  is configured in synchronous, asynchronous or asymmetric mode of
> +  execution (default: ``sync``).
>    Synchronous mode: a bad access is detected immediately when a tag
>    check fault occurs.
>    Asynchronous mode: a bad access detection is delayed. When a tag check
>    fault occurs, the information is stored in hardware (in the TFSR_EL1
>    register for arm64). The kernel periodically checks the hardware and
>    only reports tag faults during these checks.
> +  Asymmetric mode: a bad access is detected synchronously on reads and
> +  asynchronously on writes.
>
>  - ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
>    traces collection (default: ``on``).
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 8835e0784578..ebed755ebf34 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -88,7 +88,7 @@ static void kasan_test_exit(struct kunit *test)
>   */
>  #define KUNIT_EXPECT_KASAN_FAIL(test, expression) do {                 \
>         if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&                         \
> -           !kasan_async_mode_enabled())                                \
> +           kasan_sync_fault_possible())                                \
>                 migrate_disable();                                      \
>         KUNIT_EXPECT_FALSE(test, READ_ONCE(fail_data.report_found));    \
>         barrier();                                                      \
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 05d1e9460e2e..87eb7aa13918 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -29,6 +29,7 @@ enum kasan_arg_mode {
>         KASAN_ARG_MODE_DEFAULT,
>         KASAN_ARG_MODE_SYNC,
>         KASAN_ARG_MODE_ASYNC,
> +       KASAN_ARG_MODE_ASYMM,
>  };
>
>  enum kasan_arg_stacktrace {
> @@ -49,6 +50,10 @@ EXPORT_SYMBOL(kasan_flag_enabled);
>  bool kasan_flag_async __ro_after_init;
>  EXPORT_SYMBOL_GPL(kasan_flag_async);
>
> +/* Whether the asymmetric mode is enabled. */
> +bool kasan_flag_asymm __ro_after_init;
> +EXPORT_SYMBOL_GPL(kasan_flag_asymm);
> +
>  /* Whether to collect alloc/free stack traces. */
>  DEFINE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
>
> @@ -69,7 +74,7 @@ static int __init early_kasan_flag(char *arg)
>  }
>  early_param("kasan", early_kasan_flag);
>
> -/* kasan.mode=sync/async */
> +/* kasan.mode=sync/async/asymm */
>  static int __init early_kasan_mode(char *arg)
>  {
>         if (!arg)
> @@ -79,6 +84,8 @@ static int __init early_kasan_mode(char *arg)
>                 kasan_arg_mode = KASAN_ARG_MODE_SYNC;
>         else if (!strcmp(arg, "async"))
>                 kasan_arg_mode = KASAN_ARG_MODE_ASYNC;
> +       else if (!strcmp(arg, "asymm"))
> +               kasan_arg_mode = KASAN_ARG_MODE_ASYMM;
>         else
>                 return -EINVAL;
>
> @@ -116,11 +123,13 @@ void kasan_init_hw_tags_cpu(void)
>                 return;
>
>         /*
> -        * Enable async mode only when explicitly requested through
> -        * the command line.
> +        * Enable async or asymm modes only when explicitly requested
> +        * through the command line.
>          */
>         if (kasan_arg_mode == KASAN_ARG_MODE_ASYNC)
>                 hw_enable_tagging_async();
> +       else if (kasan_arg_mode == KASAN_ARG_MODE_ASYMM)
> +               hw_enable_tagging_asymm();
>         else
>                 hw_enable_tagging_sync();
>  }
> @@ -143,16 +152,24 @@ void __init kasan_init_hw_tags(void)
>         case KASAN_ARG_MODE_DEFAULT:
>                 /*
>                  * Default to sync mode.
> -                * Do nothing, kasan_flag_async keeps its default value.
> +                * Do nothing, kasan_flag_async and kasan_flag_asymm keep
> +                * their default values.
>                  */
>                 break;
>         case KASAN_ARG_MODE_SYNC:
> -               /* Do nothing, kasan_flag_async keeps its default value. */
> +               /*
> +                * Do nothing, kasan_flag_async and kasan_flag_asymm keep
> +                * their default values.
> +                */
>                 break;
>         case KASAN_ARG_MODE_ASYNC:
>                 /* Async mode enabled. */
>                 kasan_flag_async = true;
>                 break;
> +       case KASAN_ARG_MODE_ASYMM:
> +               /* Asymm mode enabled. */
> +               kasan_flag_asymm = true;
> +               break;
>         }
>
>         switch (kasan_arg_stacktrace) {
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 3639e7c8bb98..1d331ce67dec 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -14,15 +14,21 @@
>
>  DECLARE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
>  extern bool kasan_flag_async __ro_after_init;
> +extern bool kasan_flag_asymm __ro_after_init;
>
>  static inline bool kasan_stack_collection_enabled(void)
>  {
>         return static_branch_unlikely(&kasan_flag_stacktrace);
>  }
>
> -static inline bool kasan_async_mode_enabled(void)
> +static inline bool kasan_async_fault_possible(void)
>  {
> -       return kasan_flag_async;
> +       return kasan_flag_async | kasan_flag_asymm;
> +}
> +
> +static inline bool kasan_sync_fault_possible(void)
> +{
> +       return !kasan_flag_async | kasan_flag_asymm;

This should be just !kasan_flag_async.

It seems that choosing one exclusive option out of 3 via two bools is
confusing. How about an enum?

enum kasan_mode {
  KASAN_MODE_SYNC,
  KASAN_MODE_ASYNC,
  KASAN_MODE_ASYMM,
};

enum kasan_mode kasan_mode __ro_after_init;
EXPORT_SYMBOL_GPL(kasan_mode);

I also agree with Marco re using || instead of |.


>  }
>  #else
>
> @@ -31,11 +37,16 @@ static inline bool kasan_stack_collection_enabled(void)
>         return true;
>  }
>
> -static inline bool kasan_async_mode_enabled(void)
> +static inline bool kasan_async_fault_possible(void)
>  {
>         return false;
>  }
>
> +static inline bool kasan_sync_fault_possible(void)
> +{
> +       return true;
> +}
> +
>  #endif
>
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> @@ -287,6 +298,9 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>  #ifndef arch_enable_tagging_async
>  #define arch_enable_tagging_async()
>  #endif
> +#ifndef arch_enable_tagging_asymm
> +#define arch_enable_tagging_asymm()
> +#endif
>  #ifndef arch_force_async_tag_fault
>  #define arch_force_async_tag_fault()
>  #endif
> @@ -302,6 +316,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>
>  #define hw_enable_tagging_sync()               arch_enable_tagging_sync()
>  #define hw_enable_tagging_async()              arch_enable_tagging_async()
> +#define hw_enable_tagging_asymm()              arch_enable_tagging_asymm()
>  #define hw_force_async_tag_fault()             arch_force_async_tag_fault()
>  #define hw_get_random_tag()                    arch_get_random_tag()
>  #define hw_get_mem_tag(addr)                   arch_get_mem_tag(addr)
> @@ -312,6 +327,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>
>  #define hw_enable_tagging_sync()
>  #define hw_enable_tagging_async()
> +#define hw_enable_tagging_asymm()
>
>  #endif /* CONFIG_KASAN_HW_TAGS */
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 884a950c7026..9da071ad930c 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -112,7 +112,7 @@ static void start_report(unsigned long *flags)
>
>  static void end_report(unsigned long *flags, unsigned long addr)
>  {
> -       if (!kasan_async_mode_enabled())
> +       if (!kasan_async_fault_possible())
>                 trace_error_report_end(ERROR_DETECTOR_KASAN, addr);
>         pr_err("==================================================================\n");
>         add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
> --
> 2.33.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfuu3MLgeSJONqKaXMzkBsGxTQYjTtF0_%3DfMf4dGGQZCw%40mail.gmail.com.
