Return-Path: <kasan-dev+bncBDW2JDUY5AORBGGY7CFAMGQEF5COLOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 31CDB424A55
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Oct 2021 01:07:05 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id i14-20020a4a928e000000b0029acf18dcffsf2572729ooh.11
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 16:07:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633561624; cv=pass;
        d=google.com; s=arc-20160816;
        b=xdp62Lyrk8ixGgRb2EZXrTQoSZ4m29S6Iyzyzhl3jQeDaf6tTQdmZAVRIwZsVocVZt
         EDVbkZheuENol37UUzKi2jblFinOSJg6E18LOZrUOHGWyB+vWoSlKGKlnuAFbYf6rdp5
         JjJXN04T5M7ZogtzYRt5944bb4A6l/d9LY1a4xlCmIFX1iMIOI0AUjOPTrvrXrX+3Avg
         zRsuoTLtlg5hHfGgbfl1oJNqPe5MYmfDQu1dSnF9VVwtgmfVKEs2t4LxIHjTXZcfgAWB
         he5n0nsKYtwhk/6gabicAD2gGlJ5ow+BFNwa8UZGOiHGe6TRrPRGsXokf3g5Mc5i94Kq
         apfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=slgSPpRwszqa0gD+ltssjH2AnSGqcj+/ohdl3hKQClY=;
        b=EDaUDTfXb5v1UEaRYxnycmHCVgoTMuCe4KOGiZbY3ysdVFXeB/dvux62uECZ7TmydG
         eWRBZ4Y0rOMKa8KSMKUROnaCeU6JyPp0B8OQCTY7AkiO0oKf5Jr9Bf5PgswPNkKKOeTe
         jOONS/kROMsZRpupWv5sPUb27o7jcePN1vyix5XjFZVCowO4w3QxCSmKIUQ+1XzGfxPw
         c3Udf6489dZo9WpNz2FGrn4dgEQB439w6H0icC+e4Qb17tdtFrD3rEEEOMhFK8cyvZmi
         QXruJBqgu1qWTeYUdrq0hge6BlUlDl8S1ZIsXa4qXZ5D71nyxwsv3/AjJOTxl7SLrLmV
         XI8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=X6Vwq7uO;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::133 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=slgSPpRwszqa0gD+ltssjH2AnSGqcj+/ohdl3hKQClY=;
        b=f0w91pCjJvAPXNPTJWRI/tKBCBMCE8cC2IVngwnRfmn7qDzBwDjISt+G/xNTuj/PAp
         Ljmk5zGMptE6I9LFkjhqL0IH0z8W/qwFo/kbrAVPe4S5iIoJ5Jj8uLm21N4SoO4LHwy6
         YCn7xVPr/xosB4lZOhsks7Jjt4lXEANnKI7xsV/KP0IxqA9/DMkdUiH37EJzfiPCBTFN
         6UQfzrZ/bAqWxIuYpNNCnaok2IIhiR0gij+MAJ7Aj2BQJJ+7muwgCTOxk41ps/32dGOT
         VnKfOeKVYw08OwKEYbw9mPJpKCzCWvtxN9SuZz2zNWuCAWneHz1ySOkU8EsBriPVd9xy
         jIJg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=slgSPpRwszqa0gD+ltssjH2AnSGqcj+/ohdl3hKQClY=;
        b=L4gOShm0WNPs4ss3tNACxfLKKb3bLGw2ga3gLU97Pd7Ls7pQ0y6M8O/ruOQlPR6y9w
         eYLnZfnfE6zjf79m2mMQbm6iv4Q8UOT17wJ1BiyiL/6AQz9aN94XQVZuiHfXIqqfAPta
         R+VQ96YrzghV3g7rSOSuIJGtn0+zo1NvllNvLVnP4a3wir6Lg8loYf/32hlUxQL0C5Uj
         OmbxZGjnYxHfNI4OQPP8ph3BAM3/EdOeT2IrgKvEsNnJ8RtQGzXEk8nvLQVc0Z+EaU9E
         YG/kq112cEBP5C3ydZsgFwZS+XI1FIbYLkgHRmr0fsNRsqhj5Kl2+ZxYZcTbZwEO0Rg1
         Xx2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=slgSPpRwszqa0gD+ltssjH2AnSGqcj+/ohdl3hKQClY=;
        b=6UrkXtcmavXE+AhWxVtYvaTwCN81MbNfmkqZoSTARgRDV3TH4oeYLfBth3q1+/Yg6S
         i8rI9iMhcv+alJP/ASBOgjbhm/ZwyX3qhJOQ+R11xQ0BchvMtgfMU6jpEhIersULPfj9
         pT17ujTO7iaPzEVgYEfPgVId+83rNhSeMPN/ICl8XdGq3fgSAMtUpkJ1l2A+3wXGU8Im
         NOn3cArd4z8qUoytxDhvg8J77MK3tgKTEw25C3JfP0g8g4k5KUFMECpCRAPkLec2qPhd
         +sCK97OVZX2hQjYeyGgQCFhVDLuhmvMoXYtiQhOz8+SnUo6PQ5PxtDN2eSmK4vEPP2LX
         lVow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531TcwVBqL5IKIPEK9l5+TIcSS2Nxa82VUuZSxIxiVWCKmLrXrok
	+fGoFOdPsZLF+F6Qo2KRRRQ=
X-Google-Smtp-Source: ABdhPJwqEsXbzaEPA10yw8evdr9ZIUymoBQUYdrnsMqLV1m4UehiIx/J0QWMvXn1PkV6dwPEhK7W2Q==
X-Received: by 2002:a4a:d455:: with SMTP id p21mr800769oos.97.1633561624187;
        Wed, 06 Oct 2021 16:07:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1e02:: with SMTP id m2ls448526oic.2.gmail; Wed, 06 Oct
 2021 16:07:03 -0700 (PDT)
X-Received: by 2002:a54:4e94:: with SMTP id c20mr704593oiy.57.1633561623862;
        Wed, 06 Oct 2021 16:07:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633561623; cv=none;
        d=google.com; s=arc-20160816;
        b=EjElMwX+oMjH0GcYUgNLbIC01ZbAYuexgwtm2WKn9aX2yClfaoMio7yqyIwE9oC7Ck
         wvWWwPsMxMfeg71XVe3vXuJw7UcYLmtGbXGqG37pOK8Dqb8ZEwHkEFtuipEC32UsCtag
         S5E8y8pm1b0tk0EP5JBrNABiQ4rMe7q6iqW+tnqN7RmDllH9aFP8Drc7plQr0yw8Qyv2
         A564vhTw4a6tEzg1CDm8bNAJxPBOQSZiGlBus7Wyv+UPbx1c0WCwUkjLXof49mjDNQXc
         Ej3YzX9XSryg6fyLFyfi8qiObkI5Ln6fI3LwBRXZIasgagn408nF2a3f8edWGraA/IvE
         bHAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WbOa4HLIAaIjrUBwOZYmdK4mBEVDQc4YiH+cLFPMjPc=;
        b=XsEzmAFql1r616KqAXDpLGGcOgKGzwlUsYo9gt0lIONcJBFMVt5zgOvsirDnq2ZBxZ
         CYUgPVEwoDjl6uKbt+/g/l/kVGTi40iR6uahS+zIE9dp+l27keup0RHgtHOraYm2jQey
         zzrCt9IQycLpWCw8RDFnEjpOPpi3WDviqQBImd45XGwjefb8GR2vYuWUpmQnIrJX1NS5
         o265/kwtGSDxBEuIE3Mwe18PAocM8sZ4nrUHxKXvkealc3RTnfdX4OW5x/59jZd5AIBR
         1N+GLnVdBUoBckqL7gps+QvrwYU2L+WKzhdMN5dPkbBG35h+43x/WYVsOzkql3Q9G/PB
         FCeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=X6Vwq7uO;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::133 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x133.google.com (mail-il1-x133.google.com. [2607:f8b0:4864:20::133])
        by gmr-mx.google.com with ESMTPS id m30si2211224ooa.1.2021.10.06.16.07.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Oct 2021 16:07:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::133 as permitted sender) client-ip=2607:f8b0:4864:20::133;
Received: by mail-il1-x133.google.com with SMTP id w11so1223748ilv.6
        for <kasan-dev@googlegroups.com>; Wed, 06 Oct 2021 16:07:03 -0700 (PDT)
X-Received: by 2002:a05:6e02:1a69:: with SMTP id w9mr641955ilv.235.1633561623667;
 Wed, 06 Oct 2021 16:07:03 -0700 (PDT)
MIME-Version: 1.0
References: <20211006154751.4463-1-vincenzo.frascino@arm.com> <20211006154751.4463-6-vincenzo.frascino@arm.com>
In-Reply-To: <20211006154751.4463-6-vincenzo.frascino@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 7 Oct 2021 01:06:53 +0200
Message-ID: <CA+fCnZcT9oZ-Z0+OGVKa8-fjeod=TvvbXuECphTgjPrMsDSYbw@mail.gmail.com>
Subject: Re: [PATCH v3 5/5] kasan: Extend KASAN mode kernel parameter
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
 header.i=@gmail.com header.s=20210112 header.b=X6Vwq7uO;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::133
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

.On Wed, Oct 6, 2021 at 5:48 PM Vincenzo Frascino
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
>  mm/kasan/hw_tags.c                | 28 ++++++++++++++++++----------
>  mm/kasan/kasan.h                  | 31 +++++++++++++++++++++++++++----
>  mm/kasan/report.c                 |  2 +-
>  5 files changed, 52 insertions(+), 18 deletions(-)
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
> index 05d1e9460e2e..39e34595f2b4 100644
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
> @@ -45,9 +46,9 @@ static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
>  DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
>  EXPORT_SYMBOL(kasan_flag_enabled);
>
> -/* Whether the asynchronous mode is enabled. */
> -bool kasan_flag_async __ro_after_init;
> -EXPORT_SYMBOL_GPL(kasan_flag_async);
> +/* Whether the selected mode is synchronous/asynchronous/asymmetric.*/
> +enum kasan_mode kasan_mode __ro_after_init;
> +EXPORT_SYMBOL_GPL(kasan_mode);
>
>  /* Whether to collect alloc/free stack traces. */
>  DEFINE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
> @@ -69,7 +70,7 @@ static int __init early_kasan_flag(char *arg)
>  }
>  early_param("kasan", early_kasan_flag);
>
> -/* kasan.mode=sync/async */
> +/* kasan.mode=sync/async/asymm */
>  static int __init early_kasan_mode(char *arg)
>  {
>         if (!arg)
> @@ -79,6 +80,8 @@ static int __init early_kasan_mode(char *arg)
>                 kasan_arg_mode = KASAN_ARG_MODE_SYNC;
>         else if (!strcmp(arg, "async"))
>                 kasan_arg_mode = KASAN_ARG_MODE_ASYNC;
> +       else if (!strcmp(arg, "asymm"))
> +               kasan_arg_mode = KASAN_ARG_MODE_ASYMM;
>         else
>                 return -EINVAL;
>
> @@ -116,11 +119,13 @@ void kasan_init_hw_tags_cpu(void)
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
> @@ -143,15 +148,18 @@ void __init kasan_init_hw_tags(void)
>         case KASAN_ARG_MODE_DEFAULT:
>                 /*
>                  * Default to sync mode.
> -                * Do nothing, kasan_flag_async keeps its default value.
>                  */

kasan_mode = KASAN_MODE_SYNC;

then, since the "do nothing" comment is dropped.

> -               break;
>         case KASAN_ARG_MODE_SYNC:
> -               /* Do nothing, kasan_flag_async keeps its default value. */
> +               /* Sync mode enabled. */
> +               kasan_mode = KASAN_MODE_SYNC;
>                 break;
>         case KASAN_ARG_MODE_ASYNC:
>                 /* Async mode enabled. */
> -               kasan_flag_async = true;
> +               kasan_mode = KASAN_MODE_ASYNC;
> +               break;
> +       case KASAN_ARG_MODE_ASYMM:
> +               /* Asymm mode enabled. */
> +               kasan_mode = KASAN_MODE_ASYMM;
>                 break;
>         }
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 3639e7c8bb98..71b1b5d3d97e 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -13,16 +13,29 @@
>  #include "../slab.h"
>
>  DECLARE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
> -extern bool kasan_flag_async __ro_after_init;
> +
> +enum kasan_mode {
> +       KASAN_MODE_SYNC,
> +       KASAN_MODE_ASYNC,
> +       KASAN_MODE_ASYMM,
> +};
> +
> +extern enum kasan_mode kasan_mode __ro_after_init;
>
>  static inline bool kasan_stack_collection_enabled(void)
>  {
>         return static_branch_unlikely(&kasan_flag_stacktrace);
>  }
>
> -static inline bool kasan_async_mode_enabled(void)
> +static inline bool kasan_async_fault_possible(void)
> +{
> +       return kasan_mode == KASAN_MODE_ASYNC ||
> +                       kasan_mode == KASAN_MODE_ASYMM;
> +}
> +
> +static inline bool kasan_sync_fault_possible(void)
>  {
> -       return kasan_flag_async;
> +       return kasan_mode != KASAN_MODE_ASYNC;

kasan_mode == KASAN_MODE_SYNC || kasan_mode == KASAN_MODE_ASYMM

is more in line with the condition in kasan_async_fault_possible().

>  }
>  #else
>
> @@ -31,11 +44,16 @@ static inline bool kasan_stack_collection_enabled(void)
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
> @@ -287,6 +305,9 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>  #ifndef arch_enable_tagging_async
>  #define arch_enable_tagging_async()
>  #endif
> +#ifndef arch_enable_tagging_asymm
> +#define arch_enable_tagging_asymm()
> +#endif
>  #ifndef arch_force_async_tag_fault
>  #define arch_force_async_tag_fault()
>  #endif
> @@ -302,6 +323,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>
>  #define hw_enable_tagging_sync()               arch_enable_tagging_sync()
>  #define hw_enable_tagging_async()              arch_enable_tagging_async()
> +#define hw_enable_tagging_asymm()              arch_enable_tagging_asymm()
>  #define hw_force_async_tag_fault()             arch_force_async_tag_fault()
>  #define hw_get_random_tag()                    arch_get_random_tag()
>  #define hw_get_mem_tag(addr)                   arch_get_mem_tag(addr)
> @@ -312,6 +334,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
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

With the mentioned changes:

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcT9oZ-Z0%2BOGVKa8-fjeod%3DTvvbXuECphTgjPrMsDSYbw%40mail.gmail.com.
